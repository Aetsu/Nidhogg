# Monitor: indicadores visuales de progreso con `rich`

## Contexto y motivación

`nidhogg monitor` (`nidhogg/cli.py:436`, `_run_monitor`) sondea el changelog de
PyPI en un bucle infinito: por cada iteración obtiene las entradas nuevas desde
el último serial procesado, las analiza concurrentemente
(`ThreadPoolExecutor`), imprime el resultado de cada paquete a medida que
termina, persiste el nuevo serial y duerme `--interval` segundos antes de
repetir.

Hoy ese bucle es una caja negra desde fuera: no hay forma de distinguir a
simple vista si el proceso está **esperando** la siguiente comprobación,
**analizando** paquetes activamente, o colgado. El usuario quiere visibilidad
en tiempo real de en qué estado está `monitor` en cada momento, usando la
librería [`rich`](https://github.com/Textualize/rich) para mejorar la salida
de terminal.

**Alcance de esta spec: solo `monitor`.** `analyze --batch` y `fetch` quedan
fuera — no se tocan en esta iteración.

## Diseño

### Nueva dependencia

Añadir `rich` con `uv add rich`.

### Los dos estados visibles

1. **Esperando** — durante la comprobación del changelog y durante el `sleep`
   entre iteraciones cuando no hay paquetes nuevos.
2. **Procesando** — mientras el `ThreadPoolExecutor` tiene paquetes en vuelo.

Ambos se muestran solo cuando la salida es una terminal
(`sys.stdout.isatty()`), siguiendo la convención ya usada en el proyecto para
color (`writer.py`, `_run_batch`). Si la salida está redirigida (fichero, cron,
`--json` a un pipe), `monitor` mantiene el comportamiento actual (logging plano
vía loguru, sin barras ni spinners) para no ensuciar logs.

### Estado "esperando"

Al comprobar el changelog (`client.current_serial()` / `client.entries_since()`)
se muestra un spinner transitorio simple:

```python
with console.status("Comprobando PyPI..."):
    current_serial = client.current_serial()
    entries = [...]
```

Si no hay entradas nuevas (o tras terminar de procesar las que había), antes de
dormir `--interval` segundos se muestra una cuenta atrás en vivo:

```
⠋ Esperando nuevos paquetes... próxima comprobación en 42s
```

Implementada con un único `rich.progress.Progress` (`SpinnerColumn` +
`TextColumn`) actualizado una vez por segundo. Debe preservarse la propiedad
actual de que `time.sleep` se invoca **al menos una vez por iteración incluso
con `--interval 0`** (los tests parchean `time.sleep` para lanzar
`KeyboardInterrupt` y cortar el bucle; un `range(0)` que nunca llama a
`time.sleep` lo rompería):

```python
remaining = interval
if remaining <= 0:
    time.sleep(remaining)  # preserva la llamada única con interval=0
else:
    while remaining > 0:
        progress.update(task, description=f"Esperando nuevos paquetes... próxima comprobación en {remaining}s")
        time.sleep(1)
        remaining -= 1
```

### Estado "procesando"

Cuando hay entradas que analizar, se usa un `rich.progress.Progress` con:

- **Una tarea global determinada**: `Analizando paquetes` con
  `total=len(entries)`, columnas `BarColumn` + `MofNCompleteColumn` +
  `TimeElapsedColumn`. Avanza en 1 cada vez que un future completa (éxito o
  error — igual que hoy, que sigue adelante tras un `PackageReadError`).
- **Tareas transitorias por paquete**, indeterminadas (`total=None`,
  `SpinnerColumn`), que solo existen mientras ese paquete se está analizando
  *de verdad* (no mientras espera turno en la cola del executor). Se crean
  dentro de la función que se somete al pool — así, con `--concurrency 4`, se
  ven como máximo 4 filas de spinner activas a la vez, reflejando el paralelismo
  real en vez de listar las N entradas descubiertas de golpe:

```python
def _analyse_with_progress(entry, progress, keep_download):
    task_id = progress.add_task(f"  {entry.name}", total=None)
    try:
        return _analyse_new_package(entry.name, keep_download=keep_download)
    finally:
        progress.remove_task(task_id)
```

El resto de la lógica (`ThreadPoolExecutor`, `as_completed`, guardado de
history, impresión de `format_results`/JSON) no cambia — se somete
`_analyse_with_progress` en vez de `_analyse_new_package` directamente, y tras
cada `future.result()` se llama `progress.advance(overall_task)`.

### Resultado detallado por paquete: se mantiene igual

Por decisión explícita: al completarse un paquete se sigue imprimiendo la
cabecera `=== nombre ===` y el `format_results` completo, tal cual hoy.
`rich.progress.Progress` soporta imprimir por su `console` mientras la barra
está activa sin corromper el renderizado en vivo (`progress.console.print(...)`
en vez de `print(...)`), así que el cambio es mecánico: sustituir los `print()`
existentes dentro del bloque de procesamiento por `progress.console.print()`
cuando `use_rich` es `True`.

### Qué NO cambia

- Comportamiento cuando `stdout` no es una terminal (pipes, redirección,
  cron): idéntico al actual, sin `rich`.
- `analyze --batch` y `fetch`: fuera de alcance.
- Formato de `format_results` / JSON / history: sin cambios.
- Semántica de `MonitorState` / `last_serial`: sin cambios — sigue siendo el
  único mecanismo de "ya escaneado" (persistido en `monitor_state.json`),
  ortogonal a los indicadores visuales de esta spec.

## Testing

Los tests existentes (`tests/test_cli.py::test_run_monitor_*`) no capturan
`stdout` como tty, así que `use_rich` será `False` y deben seguir pasando sin
modificación. Se añade al menos un test que fuerce `sys.stdout.isatty()` a
`True` (parcheado) y verifique que `_run_monitor` no lanza excepciones con
`rich` activo (usando un `Console` con `force_terminal=True` o similar, sin
aserciones sobre el contenido visual exacto — solo que el flujo concurrente
con progreso no rompe el resultado ni el guardado de estado).
