# Salida por terminal unificada con `rich`

## Contexto y motivación

Hoy la presentación humana de Nidhogg está repartida en dos caminos
incoherentes:

- **`analyze` / `fetch` / `--batch`** (`nidhogg/output/writer.py`) usan códigos
  ANSI **manuales** (`_RST`, `_BOLD`, `_RED`, `_GREEN`, `_YELLOW`, …): una
  cabecera `package/path/risk/score/findings`, una tabla de URLs con anchos
  fijos (`loc:<22`, `method:<13`) y un `BATCH SUMMARY` con separadores `─`.
- **`monitor`** ya usa `rich` (progress bars, `console.status`, spinners) cuando
  stdout es una tty, pero la impresión de cada resultado de paquete duplica la
  lógica de `writer.py` (`=== pkg ===` + `format_results`) en dos funciones
  paralelas (`_process_entries_plain` / `_process_entries_rich`).

`rich` ya es dependencia del proyecto y se quiere coherencia visual en **toda
la CLI**. Objetivos concretos acordados:

- Migrar single y batch a `rich` manteniendo el estilo **compacto** actual
  (clave:valor, no paneles grandes).
- Refinar también los componentes de progreso de `monitor`.
- Unificar el rendering humano en un único módulo.
- Salida no-TTY (logs, CI, redirección) en texto plano sin color, legible con
  `grep`.
- JSON (`--json` / `--output`) y `build_document` **intactos**.
- Cabecera por paquete en batch/monitor más clara que `=== pkg ===`.

## Diseño

### Nuevo módulo `nidhogg/output/renderer.py`

Responsabilidad única: **presentación humana** mediante renderables `rich`.
`writer.py` queda reducido a la serialización JSON (`build_document`,
`write_results`, `_serialise_finding`, `_risk_level`). La distinción es nítida:
`writer.py` = JSON, `renderer.py` = humano.

### El `Console` único

Toda la CLI comparte un único `Console` construido una vez en `cli.py` a partir
de `sys.stdout`:

```python
def make_console(stream=None) -> Console:
    stream = stream or sys.stdout
    is_tty = getattr(stream, "isatty", lambda: False)()
    return Console(
        file=stream,
        force_terminal=is_tty,
        color_system="auto" if is_tty else None,
        highlight=False,
    )
```

Cuando stdout no es una tty, `color_system=None` hace que `rich` emita **texto
plano sin ANSI** automáticamente — no se mantiene lógica de color manual. Esto
sustituye al patrón actual `use_color = sys.stdout.isatty()` esparcido por
`cli.py` y `writer.py`.

### API pública de `renderer.py`

| Función | Devuelve | Uso |
|---|---|---|
| `make_console(stream=None)` | `Console` | Único punto de construcción; shared por single/batch/monitor. |
| `render_package_result(analysis, *, display_name=None)` | `Group` (cabecera meta + score + tabla) | Single y cada paquete en batch. |
| `render_empty(analysis, *, display_name=None)` | `Text` verde `● name: no URLs found` | Atajo cuando no hay findings. |
| `render_package_header(name, verdict, score)` | `Text`/`Rule` con `name` + veredicto inline | Cabecera por paquete en batch/monitor (sustituye `=== pkg ===`). |
| `render_findings_table(findings, pkg_path)` | `Table` sin bordes (`box=None` o `SIMPLE_HEAD`) con cols `LOC`, `Method`, `Conf`, `URL` | Tabla compacta, estilo actual. |
| `render_score_bar(score)` | `Text` con `████████░░ 82%` coloreado | Reemplaza `_score_bar`. |
| `render_batch_summary(results)` | `Group` (rule + "BATCH SUMMARY" + conteos + lista flagged) | Resumen `--batch`. |
| `render_progress(*, description, total, console)` | `Progress` (Spinner + Bar + MofN + Elapsed) | Progreso global del monitor; el llamador lo usa en `with`. |
| `render_status(message, *, console)` | envoltorio sobre `console.status(message)` | "Comprobando PyPI…" (spinner estático). |
| `render_countdown(interval, *, console)` | bucle con `Progress`(Spinner + Text) que actualiza la descripción cada segundo | Countdown "Esperando nuevos paquetes… próxima comprobación en Ns"; preserva `time.sleep` al menos una vez. |

### Colores y umbrales

Las constantes ANSI (`_RST`, `_BOLD`, `_DIM`, `_RED`, `_GREEN`, `_YELLOW`,
`_RISK_COLORS`) se eliminan. Se sustituyen por `Style`/`Text` de `rich`:

- Confianza: `>= high_display` → rojo (`bold red`); `>= medium_display` →
  amarillo (`yellow`); resto → `dim`.
- Score: `>= 0.85` → rojo; `>= 0.5` → amarillo; resto → dim. (Mismos umbrales
  que `_score_bar` actual, leídos de `load_scoring_config().thresholds`.)
- Veredicto: `MALICIOUS` → `bold red`; `NOT_MALICIOUS` / clean → `green`.
- Tags inline en la URL: `[LE]` (amarillo, cuando `cert_issuer` contiene
  "Let's Encrypt"), `[PHISHING]`/`[EXFILTRATION]`/… (rojo, `domain_threat.value
  .upper()`). Misma semántica que `_fmt_finding` actual.

### Layout compacto (mantiene el estilo actual)

`render_package_result` produce un `Group` con, aproximadamente:

```
package  <bold name>
path     <dim path>

risk     <MALICIOUS|CLEAN coloreado>
score    <barra coloreada>  82%
findings <N>

URLs:
  <Table: LOC  Method  Conf  URL[tags]>
```

Sin `Panel` envolvente (decisión: estilo compacto). La cabecera por paquete
(`render_package_header`) en batch/monitor se imprime **antes** del
`render_package_result` cuando hay findings; cuando no los hay se imprime solo
`render_empty` (línea verde, sin header) — mismo comportamiento que el `if
analysis.findings:` actual en `_run_batch`/`_process_entries_*`.

### Data flow por subcomando

- **`_run_analyze` / `_run_fetch`** (rama no-JSON): se construye
  `console = make_console()` y se reemplaza `print(format_results(analysis,
  color=use_color))` por `console.print(render_package_result(analysis))`. El
  flag `--json`/`--output` sigue sin tocar el console.
- **`_run_batch`**: bucle imprime, por paquete con findings,
  `console.print(render_package_header(name, verdict, score))` seguido de
  `console.print(render_package_result(analysis, display_name=pkg_dir.name))`;
  sin findings, `console.print(render_empty(...))`. Al final
  `console.print(render_batch_summary(results))`. JSON/`--output` intactos.
- **`_process_entries_plain` / `_process_entries_rich`**: dejan de duplicar la
  impresión. Ambas llaman a `render_package_header` + `render_package_result`
  (impresos vía el `console` del modo plain, o `progress.console.print(...)`
  en rich). **Esta es la unificación principal**: un único camino de rendering
  humano para single, batch y monitor.
- **`_run_monitor_iteration_rich` / `_wait_before_next_poll_rich` /
  `_analyse_with_progress`**: refactor a usar `render_status` (para
  "Comprobando PyPI…"), `render_progress` (barra global "Analizando paquetes")
  y `render_countdown` (cuenta atrás entre iteraciones) de `renderer.py`. Las
  columnas del progreso (`SpinnerColumn`, `BarColumn`, `MofNCompleteColumn`,
  `TimeElapsedColumn`) se mantienen — solo se centralizan. Se preserva la
  propiedad crítica: en `--interval 0` se invoca `time.sleep` **al menos una
  vez** (los tests parchean `time.sleep` para lanzar `KeyboardInterrupt`).

### Manejo de errores y edge cases

- `PackageReadError` y los `print(f"Error: {exc}", file=sys.stderr)` puntuales
  se **mantienen literales** (stderr directo). No se introduce un segundo
  `Console` para dos mensajes de error.
- `ValueError` al relativizar el path del finding (`finding.filepath
  .relative_to(pkg_path)`) se trata igual que hoy: fallback al path absoluto,
  en la celda `LOC` de la tabla.
- `analysis.findings` vacío en batch/monitor: mismo guard que hoy — no se
  imprime header, solo `render_empty`.
- `--keep-download`, `--history-dir`, `--last`, `--concurrency`, `--benign
  -domains`, `--check-ssl`: sin cambios funcionales; solo la capa de
  presentación se ve afectada.

### Eliminaciones de `writer.py`

Se eliminan de `writer.py`: `format_results`, `format_batch_summary`,
`_fmt_finding`, `_score_bar`, `_c`, y las constantes ANSI (`_RST`, `_BOLD`,
`_DIM`, `_RED`, `_GREEN`, `_YELLOW`, `_RISK_COLORS`). Permanecen: `_risk_level`,
`build_document`, `write_results`, `_serialise_finding` (todo lo relacionado
con JSON). `_risk_level` queda en `writer.py` porque `build_document` lo usa y
porque `cli._run_batch` ya lo referencia para `format_batch_summary`; tras la
migración, `_run_batch` pasará a usar `render_batch_summary` que internamente
deriva el risk del score (igual que `_risk_level`), manteniendo
`_risk_level` público para `build_document`.

## Testing

- `tests/test_output_writer.py`: los tests de `format_results` se **migran** a
  un nuevo `tests/test_renderer.py`. Los renderables no son strings, así que
  los tests construyen un `console = make_console(io.StringIO())` con
  `force_terminal=False` + `color_system=None`, hacen `console.print(renderable)`
  y capturan con `console.export_text()`. Las aserciones de subcadenas se
  mantienen: `"[LE]"`, `"[PHISHING]"`, `"no URLs found"`, `"MALICIOUS"`,
  `"BATCH SUMMARY"`. Mismo contenido semántico, otra forma de captura.
- Tests de `write_results`, `build_document`, `_serialise_finding` y campos
  JSON se quedan en `test_output_writer.py` **intactos** (no tocan
  `format_results`).
- Nuevos tests en `test_renderer.py`: `render_batch_summary` (conteos por
  risk, agrupación, lista de flagged con score), `render_package_header`
  (nombre + veredicto inline), `make_console` (TTY produce color, no-TTY no
  emite ANSI — verificar que `export_text()` no contiene `\x1b[` cuando
  `color_system=None`), `render_score_bar` (umbrales 0.85/0.5).
- Monitor: revisar `tests/test_cli.py` (o donde vivan los tests de monitor):
  las aserciones sobre `=== pkg ===` se actualizan a la nueva cabecera; los
  tests no-TTY siguen pasando porque `color_system=None`.
- Verificación final:
  `uv run ruff check && uv run ruff format --check && uv run mypy && uv run pytest`.

## Fuera de alcance (YAGNI)

- No se tocan `--json`, `--output`, `build_document`, ni `output/history.py`.
- No se añade `--color={auto,always,never}` — el TTY decide.
- No paneles envolventes grandes, ni gradientes, ni árbol de findings por
  archivo (estilo compacto acordado).
- No se rediseña el documento JSON ni los campos del summary JSON.
