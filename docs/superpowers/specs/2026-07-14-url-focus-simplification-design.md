# Nidhogg: simplificación a foco exclusivo en URLs

## Contexto y motivación

Nidhogg ha ido acumulando capacidades más allá de su objetivo original (extraer y
clasificar URLs candidatas a maliciosas dentro de paquetes PyPI):

- **Layer 3** (`analysis/layer3_patterns.py`, 1381 líneas): detección de patrones de
  comportamiento (exec, network, filesystem, credential, persistence, obfuscation,
  exfiltration) y de build hooks sospechosos en `pyproject.toml`.
- **Typosquatting** (`analysis/typosquat.py`, `enrichment/pypi_metadata.py`,
  `typosquat_config.py`, ~975 líneas): comparación del nombre del paquete contra el
  top-5000 de PyPI, más enriquecimiento vía RDAP/metadata de PyPI (edad de dominio
  del email del autor, similitud de descripción, etc.). Este último fue una
  funcionalidad deliberadamente diseñada (ver
  `2026-07-08-typosquat-metadata-signals-design.md`), pero no encaja con el nuevo
  foco del proyecto.

Ninguna de las dos señales opera sobre URLs: la primera analiza comportamiento de
código, la segunda analiza el nombre del paquete y metadata de su autor. Mantenerlas
duplica la superficie del proyecto y complica el pipeline, el modelo de datos, el
scoring y la CLI sin aportar a la pregunta central: *¿qué URLs contiene este paquete
y son maliciosas?*

Esta spec decide **eliminar ambos subsistemas** y **simplificar el classifier/scoring**
a un veredicto binario, dejando el proyecto centrado exclusivamente en:

```
walker → [layer1_regex, layer2_ast] → aggregator → enrichment(ssl_cert) → classifier → output
```

`fetching/` (subcomandos `fetch`/`monitor`) y `output/history.py` quedan fuera de
esta spec: son mecanismos de descubrimiento/persistencia ortogonales al análisis en
sí y no requieren cambios.

## Qué se elimina

| Elemento | Motivo |
|---|---|
| `nidhogg/analysis/layer3_patterns.py` | Detección de comportamiento, no de URLs |
| `nidhogg/analysis/typosquat.py` | Similitud de nombre de paquete, no URLs |
| `nidhogg/enrichment/pypi_metadata.py` | Enriquecimiento RDAP/PyPI del typosquat |
| `nidhogg/typosquat_config.py` | Config exclusiva del typosquat |
| `nidhogg/data/typosquat.toml` | Datos exclusivos del typosquat |
| `nidhogg/data/top_pypi_packages.json` | Datos exclusivos del typosquat |
| `PatternCategory`, `PatternFinding` (`core/models.py`) | Modelos de layer 3 |
| `TyposquatMethod`, `TyposquatFinding` (`core/models.py`) | Modelos de typosquat |
| Campos `pattern_findings`, `typosquat` en `PackageAnalysis` | Ya sin productor |
| Llamada a `check_pyproject_hooks`/`extract_patterns` en `walker.py` | Layer 3 |
| Flags CLI `--no-check-typosquat`, `--no-typosquat-intel` (`analyze`/`fetch`/`monitor`) | Sin funcionalidad que controlar |
| Parámetros `run_typosquat`, `typosquat_intel`, `package_name`-para-typosquat en `cli.py` | Idem |
| Secciones "Patterns:" / "Typosquat:" en `output/writer.py` (texto y JSON) | Sin datos que mostrar |
| Bloques `pattern_confidence`, `combo_bonuses.typosquat_*`, `verdict_alignment` en `scoring.toml`/`scoring.py` | Señales que ya no existen |
| Tests: `test_layer3_patterns.py`, `test_typosquat*.py`, `test_pypi_metadata.py` y sus fixtures | Cubren código eliminado |

## Qué se mantiene sin cambios

- `analysis/layer1_regex.py`, `analysis/layer2_ast.py`: extracción de URLs (literal,
  concatenación, base64, f-string, scope tracking). El flag `uses_dynamic_execution`
  (emitido por layer 2 cuando una URL es irresoluble por `eval`/`exec`) se conserva:
  es una señal sobre la propia resolución de URLs, no sobre comportamiento genérico.
- `analysis/aggregator.py`, `data/benign_domains.txt`: deduplicación, normalización y
  filtrado de URLs benignas.
- `analysis/domain_classifier.py`, `data/suspicious_domains.toml`: clasificación de
  amenaza del dominio (`shortener`, `tunneling`, `exfiltration`, `ip_recon`,
  `malware_hosting`, `suspicious_tld`, `raw_ip`).
- `enrichment/ssl_cert.py`: boost de confianza cuando el dominio sirve un
  certificado Let's Encrypt.
- `fetching/` (`pypi_fetch.py`, `changelog.py`, `monitor_state.py`): sin cambios.
- `output/history.py`: sin cambios.

## Modelo de datos

`PackageAnalysis` (`core/models.py`) queda:

```python
@dataclass
class PackageAnalysis:
    name: str
    path: Path
    findings: list[UrlFinding] = field(default_factory=list)
    uses_dynamic_execution: bool = False
    score: float = 0.0
```

`UrlFinding` no cambia (`value`, `filepath`, `lineno`, `layer`, `method`,
`confidence`, `cert_issuer`, `domain_threat`).

Enums que permanecen: `AnalysisLayer`, `DetectionMethod`, `DomainThreatCategory`.
Se eliminan `PatternCategory`, `TyposquatMethod`.

## Classifier: veredicto binario

`classifier.py` pasa de 3 estados (`MALICIOUS`/`SUSPICIOUS`/`CLEAN`) a 2:

```python
class Verdict(enum.Enum):
    MALICIOUS = "malicious"
    NOT_MALICIOUS = "not_malicious"
```

Reglas evaluadas en orden:

1. Sin `findings` y sin `uses_dynamic_execution` → `NOT_MALICIOUS`.
2. Algún finding con `domain_threat` en `{EXFILTRATION, MALWARE_HOSTING}` →
   `MALICIOUS`.
3. `uses_dynamic_execution` → `MALICIOUS`.
4. `max(confidence de findings) >= thresholds.malicious_url` → `MALICIOUS`.
5. En cualquier otro caso → `NOT_MALICIOUS`.

El score numérico (`analysis.score`, `[0.0, 0.99]`) se sigue calculando y
exponiendo junto al veredicto (para quien quiera matizar), pero con una fórmula
más simple.

## Scoring simplificado

`scoring.py` se recorta a lo que el classifier y `aggregator`/`ssl_cert` necesitan:

```toml
[thresholds]
malicious_url = 0.85

[domain_boosts]
high = 0.2      # EXFILTRATION / MALWARE_HOSTING
normal = 0.1    # resto de categorías
confidence_cap = 0.99

[ssl]
confidence_bump = 0.05

[score]
domain_floor = 0.9   # score mínimo si hay EXFILTRATION/MALWARE_HOSTING
```

Estos tres valores (`domain_boosts.high`, `domain_boosts.normal`,
`ssl.confidence_bump`) se dejan deliberadamente en sus niveles preexistentes
en lugar de retunearlos, para no mezclar un cambio de sensibilidad de
detección con un refactor estructural.

Se eliminan: `pattern_confidence`, `combo_bonuses.high_severity_url`,
`combo_bonuses.dynamic_execution`, `combo_bonuses.typosquat_*`,
`verdict_alignment.*` (los 3 tramos ya no aplican), `count_saturation`,
`min_count_factor`, `max_weight`/`avg_weight` (se sustituyen por un cálculo directo).

`compute_score` nuevo:

```python
def compute_score(analysis: PackageAnalysis) -> float:
    confidences = [f.confidence for f in analysis.findings]
    score = max(confidences, default=0.0)
    if analysis.uses_dynamic_execution:
        score = max(score, cfg.thresholds.malicious_url)
    if any(f.domain_threat in _MALICIOUS_DOMAIN_THREATS for f in analysis.findings):
        score = max(score, cfg.score.domain_floor)
    return min(score, 0.99)
```

Sin `avg`/count-factor: con veredicto binario, la métrica relevante es "el hallazgo
más fuerte", no un promedio que diluye una única URL claramente maliciosa entre
muchas URLs benignas del mismo paquete.

## CLI

`analyze`/`fetch`/`monitor` pierden `--no-check-typosquat` y
`--no-typosquat-intel`. `fetch` deja de aceptar/usar `package_name` para typosquat
(solo se usa ya para nombrar/localizar el paquete descargado). Resto de flags
(`--benign-domains`, `--check-ssl`, `--json`, `--output`, `--verbose`, etc.) sin
cambios.

## Output

`output/writer.py`: se eliminan las secciones "Patterns:" y "Typosquat:" (texto y
JSON), y los contadores asociados (`total_pattern_findings`,
`author_domain_age_days`, etc.). El summary y el bloque de findings de URL
(dominio, confianza, capa, método, `cert_issuer`, `domain_threat`) se mantienen
igual, sustituyendo el label de veredicto por los 2 nuevos valores.

## Testing

- Eliminar: `tests/test_layer3_patterns.py`, `tests/test_typosquat.py` (o
  equivalente), `tests/test_pypi_metadata.py`, `tests/test_typosquat_config.py` y
  sus fixtures en `tests/fixtures/` que sean exclusivas de esos módulos.
- Actualizar: `tests/test_classifier.py` (veredicto binario), `tests/test_scoring.py`
  (fórmula nueva), `tests/test_aggregator.py` (sin cambios de fondo, verificar que
  sigue pasando sin las señales eliminadas), `tests/test_cli.py` (flags eliminados),
  `tests/test_writer.py` (secciones eliminadas).
- `pyproject.toml`: revisar si alguna dependencia (p. ej. cliente HTTP usado solo
  por RDAP) queda huérfana y puede quitarse con `uv remove`.

## Fuera de alcance

- `fetching/` y sus subcomandos `fetch`/`monitor`: sin cambios funcionales más allá
  de perder los flags de typosquat ya listados arriba.
- `output/history.py`: sin cambios.
- No se introduce integración con VirusTotal ni ningún otro threat-intel externo
  nuevo; la clasificación de URL maliciosa sigue basándose en las reglas estáticas
  de `domain_classifier.py` + el enriquecimiento SSL existente.
