# Diseño: enriquecimiento HTTP (`--check-http`)

Fecha: 2026-07-17

## Objetivo

Añadir un flag opcional que, para cada URL encontrada, haga una petición HTTP y
guarde el **código de respuesta** y el **título** de la página. Es un paso de
enriquecimiento opcional que requiere acceso a red, análogo a `--check-ssl`.

## Motivación

Una URL viva que responde 200 con un título coherente aporta contexto sobre si el
endpoint sigue activo y qué sirve. Es señal útil para priorizar findings.

## Modelo de datos

Dos campos nuevos en `UrlFinding` (`nidhogg/core/models.py`):

```python
http_status: int | None = None   # status HTTP final tras redirects
http_title: str | None = None    # <title> limpio, truncado a 200 chars
```

`None` significa: no comprobado, o comprobado pero sin respuesta/sin título.

## Módulo nuevo: `nidhogg/enrichment/http_probe.py`

Espeja la estructura de `enrichment/ssl_cert.py`.

### API pública

```python
def check_urls(findings: list[UrlFinding], *, timeout: float = 5.0) -> list[UrlFinding]
```

- Agrupa URLs **únicas** por su valor; solo esquemas `http`/`https`. El resto se
  ignora en silencio.
- `ThreadPoolExecutor` con `_MAX_WORKERS = 10` (igual que ssl_cert).
- Muta los findings en sitio y devuelve la misma lista.
- Todos los findings que comparten una misma URL reciben el mismo resultado.

### Helper privado

```python
def _probe(url: str, *, timeout: float) -> tuple[int, str | None] | None
```

- GET con `urllib.request` (stdlib — sin dependencias nuevas), **sigue redirects**
  (comportamiento por defecto de `urllib`), guarda el status final.
- Lee el body con **tope de tamaño ~64 KB** (`resp.read(_MAX_BODY_BYTES)`) para no
  descargar contenido grande.
- Decodifica el body como UTF-8 con `errors="replace"`.
- Extrae `<title>` con `html.parser.HTMLParser` (stdlib): subclase que captura el
  texto entre `<title>` y `</title>`.
- Limpia el título: `strip()`, colapsa espacios en blanco a uno solo, trunca a 200
  chars.
- Devuelve `(status, title)`; `title` es `None` si no hay `<title>` o body no-HTML.
- Cualquier excepción (timeout, conexión, HTTP error con status → se captura el
  status si está disponible, si no `None`) → log debug y `None`, sin romper el
  pipeline.

### Seguridad

- Solo se activa con el flag explícito `--check-http` (opt-in de red), igual que
  `--check-ssl`.
- Nunca ejecuta código de los paquetes; solo hace una petición HTTP GET al host.
- Tope de tamaño de body + timeout evitan cuelgues y descargas grandes.
- El texto de ayuda del flag advierte que requiere acceso a red.

## CLI (`nidhogg/cli.py`)

- Nuevo flag `--check-http` (`action="store_true"`, `dest="check_http"`) en el
  subparser `analyze` (aplica también a `--batch`, como `--check-ssl`).
- Se propaga por `_analyse_one(..., check_http: bool = False)`,
  `_run_analyze`, `_run_batch`.
- Cuando `check_http` es `True`: import perezoso de
  `nidhogg.enrichment.http_probe.check_urls` y llamada con `analysis.findings`.
- Alcance: solo `analyze` (igual que `--check-ssl`). `fetch`/`monitor` no lo exponen.

## Salida

### JSON (`nidhogg/output/writer.py`)

`_serialise_finding` añade dos claves:

```python
"http_status": finding.http_status,
"http_title": finding.http_title,
```

### Humana (`nidhogg/output/renderer.py`)

En `render_file_block`, tras la URL:
- si `http_status` no es `None`: añadir `[200]` (verde si 2xx, amarillo si 3xx,
  rojo si 4xx/5xx, dim en otro caso).
- si `http_title` no es `None`: añadirlo en estilo `dim` tras el status.

## Tests (`tests/test_http_probe.py`)

Un test por caso, con `urllib` mockeado (sin red real):

- `test_probe_200_con_titulo_guarda_status_y_titulo`
- `test_probe_redirect_guarda_status_final`
- `test_probe_body_no_html_sin_titulo`
- `test_probe_timeout_devuelve_none`
- `test_probe_http_error_guarda_status_del_error`
- `test_titulo_se_limpia_y_trunca`
- `test_check_urls_ignora_esquemas_no_http`
- `test_check_urls_urls_duplicadas_comparten_resultado`

## Fuera de alcance (YAGNI)

- No reintentos ni backoff.
- No `fetch`/`monitor` (solo `analyze`).
- No parseo de meta/description ni otros campos de la página.
- No caché en disco de resultados HTTP.
