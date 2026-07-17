# Eliminar score y confidence

**Fecha**: 2026-07-16  
**Estado**: Aprobado

## Contexto

El sistema actual de scoring y confidence tiene problemas fundamentales:

1. **Score global**: Es redundante con el veredicto, no agrega información más allá del máximo de confidence, y tiene un `domain_floor` redundante.
2. **Confidence por finding**: Valores arbitrarios sin calibración empírica que crean ilusión de precisión. Ningún método base alcanza el threshold de MALICIOUS (0.85) sin domain boost.

## Decisión

Eliminar ambos conceptos (score y confidence) y el clasificador. El sistema solo mostrará las URLs encontradas con datos cualitativos (método de detección, threat category, etc.).

## Cambios

### Modelo de datos

**`UrlFinding`**:
- Eliminar campo `confidence: float`

**`PackageAnalysis`**:
- Eliminar campo `score: float`

### Módulos a eliminar completamente

| Módulo | Contenido |
|--------|-----------|
| `nidhogg/scoring.py` | `ScoringConfig`, `Thresholds`, `ScoreWeights`, `compute_score()`, `load_scoring_config()` |
| `nidhogg/classifier.py` | `Verdict` enum, `classify()` |
| `nidhogg/data/scoring.toml` | Configuración de thresholds, boosts, weights |

### Módulos a modificar

#### `nidhogg/core/models.py`
- Eliminar `confidence` de `UrlFinding`
- Eliminar `score` de `PackageAnalysis`

#### `nidhogg/analysis/layer1_regex.py`
- Eliminar `confidence=0.45` en URL findings
- Eliminar `confidence=0.80` en IP findings

#### `nidhogg/analysis/layer2_ast.py`
- Eliminar parámetro `confidence` de `_emit()`
- Eliminar todos los valores de confidence en llamadas a `_emit()`

#### `nidhogg/analysis/aggregator.py`
- Eliminar `domain_boosts` y la lógica de boost de confidence
- Mantener `classify_domain()` y asignación de `domain_threat`
- Simplificar deduplicación: ante URLs duplicadas, mantener el primer finding (sin comparar confidence)

#### `nidhogg/enrichment/ssl_cert.py`
- Eliminar `confidence_bump` y la modificación de confidence
- Mantener `cert_issuer` como dato informativo

#### `nidhogg/output/renderer.py`
- Eliminar `render_score_bar()`
- Eliminar columna "Conf" de la tabla de findings
- Eliminar styling por confidence thresholds
- Eliminar `score` de `render_package_header()`
- Eliminar `render_batch_summary()` o simplificarlo sin score
- Eliminar `_BATCH_SCORE_THRESHOLD`
- Eliminar `_risk_level()` (o moverlo si se usa en writer)

#### `nidhogg/output/writer.py`
- Eliminar `score` del summary en `build_document()`
- Eliminar `confidence` de `_serialise_finding()`
- Eliminar `_risk_level()` (ya no hay risk_level)

#### `nidhogg/cli.py`
- Eliminar passing de `analysis.score` a `render_package_header()`
- Eliminar manejo de `Verdict` (ya no hay clasificación)
- Simplificar `_analyse_one()` para no llamar a `classify()`
- Eliminar exit codes basados en MALICIOUS (siempre retornar 0 si no hay error)
- Actualizar docstrings que mencionan "confidence" o "score"

### Web (site/)

#### `site/index.html`
- Eliminar columna "Score" del thead
- Eliminar columna "Conf." del thead

#### `site/app.js`
- Eliminar `statusBadge()` (ya no hay risk_level)
- Eliminar renderizado de score en `renderResultsTable()`
- Eliminar `finding.confidence.toFixed(2)` de `findingCells()`
- Eliminar `emptyFindingCells()` para confidence
- Eliminar filtro "Malicious only" (ya no hay risk_level para filtrar)

#### `site/style.css`
- No hay cambios necesarios (los estilos son genéricos)

#### `site/data/results.json`
- Formato actualizado:
  - Eliminar `score` de cada package
  - Eliminar `risk_level` de cada package
  - Eliminar `confidence` de cada finding

### Tests

#### Tests a eliminar completamente
- `tests/test_scoring.py`
- `tests/test_classifier.py`

#### Tests a actualizar
- `tests/test_layer1_regex.py`: eliminar assertions sobre confidence
- `tests/test_layer2_ast.py`: eliminar `test_confidence_higher_than_regex_layer`
- `tests/test_aggregator.py`: eliminar tests de confidence boost, actualizar deduplicación
- `tests/test_renderer.py`: eliminar tests de score bar, confidence styling
- `tests/test_output_writer.py`: eliminar tests de score, confidence, risk_level
- `tests/test_cli.py`: actualizar tests que verifican "score" en output
- `tests/test_walker.py`: eliminar confidence de fixtures
- `tests/test_ssl_cert.py`: eliminar assertions sobre confidence bump
- `tests/test_integration.py`: actualizar si verifica score/confidence

## Flujo resultante

```
walker → [layer1, layer2] → aggregator (dedup + domain_threat) → enrichment (cert_issuer) → output
```

Sin classifier, sin score, sin confidence.

## Output resultante

### CLI (human-readable)
```
package  evil-package
path     /path/to/package

findings 3

URLs:
file.py:42   ast    base64    http://185.220.101.44/drop.sh [RAW_IP]
file.py:58   ast    fstring   https://discord.com/api/webhooks/... [EXFILTRATION]
telemetry.py:11  regex  literal  https://webhook.site/... [EXFILTRATION]
```

### JSON
```json
{
  "package": {
    "name": "evil-package",
    "path": "/path/to/package"
  },
  "summary": {
    "total_findings": 3
  },
  "findings": [
    {
      "url": "http://185.220.101.44/drop.sh",
      "file": "file.py",
      "line": 42,
      "layer": "ast",
      "method": "base64",
      "cert_issuer": null,
      "domain_threat": "raw_ip"
    }
  ]
}
```

## Consideraciones futuras

El usuario mencionó que "ya plantearemos un nuevo modelo" de clasificación. Este diseño deja el sistema preparado para:
- Agregar un nuevo clasificador basado en reglas distintas
- Implementar scoring basado en otras señales (no confidence)
- Mantener la separación clara entre detección y clasificación
