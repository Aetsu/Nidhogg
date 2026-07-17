# Output y persistencia (historial JSONL, cache con timestamp, desglose de señales) — Diseño

**Fecha:** 2026-07-08
**Grupo:** 2 de 3 (depende de los campos nuevos de [[2026-07-08-typosquat-metadata-signals-design]] para el desglose humano; independiente de fetch/monitor)

## Objetivo

Tres mejoras de salida/persistencia inspiradas en PyMongoose:
1. Log histórico append-only en JSONL, opt-in.
2. Timestamp de última actualización en el cache de top-packages.
3. Desglose de señales de typosquat en la salida humana (texto) y en el JSON.

## 1. Historial JSONL

Nuevo flag `--history-dir PATH`, disponible en `analyze`, `fetch`, `batch` y `monitor`
(ver [[2026-07-08-pypi-fetch-monitor-design]] para los dos últimos). Desactivado por
defecto — no escribe disco sin permiso explícito.

```python
# nidhogg/output/history.py
def append_finding(history_dir: Path, document: dict[str, object]) -> Path:
    """Apendea *document* (el mismo dict de build_document) a
    <history_dir>/YYYY-MM-DD.jsonl, creando el directorio si hace falta.
    Devuelve la ruta del fichero escrito."""
```

Se llama desde `cli.py` justo después de `build_document(analysis)`, solo si
`history_dir is not None`. Un fallo de escritura (permisos, disco lleno) se loggea
como warning y no aborta el análisis — la persistencia es una conveniencia, no
un requisito del pipeline.

## 2. Timestamp en cache de top-packages

Formato actual de `data/top_pypi_packages.json`: `["requests", "numpy", ...]`.
Nuevo formato: `{"fetched_at": "2026-07-08T00:00:00+00:00", "packages": [...]}`.

`_load_top_packages()` en `typosquat.py` acepta ambos formatos (lista → legacy,
sin timestamp; dict → nuevo) para no requerir migración del fichero bundleado en
el mismo commit que lo reescribe `update_top_packages()`.

```python
def top_packages_last_updated() -> datetime | None:
    """None si el fichero está en formato legacy (sin timestamp) o no tiene la clave."""
```

`cli.py` usa esto para imprimir un aviso (no bloqueante) si el cache tiene más de
30 días (constante en `typosquat.toml`, sección `[cache]`, `max_age_days = 30`):

```
Aviso: la lista de top-packages tiene 45 días. Considera --update-top-packages.
```

## 3. Desglose de señales en salida humana

`output/writer.py::format_results` — cuando `analysis.typosquat is not None`, añade
líneas por cada campo no-`None` del finding, siguiendo el formato ANSI existente:

```
Typosquat: mi-paquete ~ requests (levenshtein, distancia 1)
  Confianza: 0.60 → 0.85 (ajustada)
  Similitud descripción: 0.72
  Overlap keywords/clasificadores: 0.40
  Repo compartido: https://github.com/psf/requests
  Delta completitud metadata: +0.35
  Edad dominio email autor: 4 días
```

Campos con valor `None` se omiten (no se imprime la línea). Sin enriquecimiento,
solo se imprime la primera línea con la confianza base (comportamiento actual
extendido, no reemplazado).

`output/writer.py::build_document` — incluye los mismos campos nuevos en el dict
JSON de salida (siempre, con `null` cuando no aplica), consistente con cómo ya se
serializan `cert_issuer`/`domain_threat` en `UrlFinding`.

## Testing

- `test_output_writer.py`: casos con `TyposquatFinding` enriquecido y sin enriquecer,
  verificando qué líneas aparecen/desaparecen en texto y en JSON.
- `test_typosquat.py` (o nuevo `test_top_packages_cache.py`): carga de ambos formatos
  de `top_pypi_packages.json`, `top_packages_last_updated()` con y sin timestamp.
- Nuevo `test_history.py`: `append_finding` crea fichero con nombre de fecha correcto,
  acumula líneas en llamadas sucesivas, no rompe si el directorio no existe aún.
