# Typosquat mejorado (variantes + señales de metadata PyPI + scoring de dos capas) — Diseño

**Fecha:** 2026-07-08
**Grupo:** 1 de 3 (independiente; los otros dos son output/persistencia y fetch/monitor)

## Objetivo

Ampliar `analysis/typosquat.py` con más algoritmos de detección de nombre, añadir
señales de riesgo basadas en metadata PyPI + RDAP cuando ya hay un match léxico, y
propagar ese refuerzo a un score de dos capas (`confidence` base vs `adjusted_confidence`).

Inspirado en PyMongoose (`/Users/alpha/TEMP/PyMongoose`), adaptado a las convenciones
de Nidhogg (dataclasses, sin dependencias nuevas, config en TOML).

## Modelos (`core/models.py`)

```python
class TyposquatMethod(enum.Enum):
    LEVENSHTEIN = "levenshtein"
    TRANSPOSITION = "transposition"
    SUBSTITUTION = "substitution"    # ahora con tabla de pares ampliada (ver abajo)
    AFFIX = "affix"
    PLURALIZATION = "pluralization"  # nuevo

@dataclass
class TyposquatFinding:
    package_name: str
    similar_to: str
    distance: int
    method: TyposquatMethod
    confidence: float = 0.0                   # nuevo; 0.0 hasta que check_typosquatting lo asigna
    adjusted_confidence: float | None = None  # nuevo, tras boost de metadata
    description_similarity: float | None = None
    classifier_overlap: float | None = None
    shared_repo_url: str | None = None
    completeness_delta: float | None = None
    author_domain_age_days: int | None = None
```

Todos los campos nuevos son opcionales y quedan en `None` cuando el enriquecimiento
de red no corrió o falló — sin regresión para el código/tests existentes.

## Config nueva: `nidhogg/data/typosquat.toml`

```toml
[levenshtein]
max_distance = 1

[confidence]
levenshtein = 0.6
transposition = 0.55
substitution = 0.55
pluralization = 0.4
affix = 0.35

# Pares [candidato, objetivo] que NUNCA se reportan aunque matcheen.
known_exceptions = [
    ["request", "requests"],
]
```

Loader `nidhogg/typosquat_config.py` (mismo patrón que `scoring.py`): dataclasses
`frozen`, `functools.cache`, lectura vía `importlib.resources`.

## `analysis/typosquat.py`

**Nota de diseño — por qué NO se añaden `omission`/`repetition`/`keyboard`:**
Nidhogg ya ejecuta `_check_levenshtein` (distancia ≤ `max_distance`, por defecto 1)
contra **toda** la lista top-5000, y ese check corre primero. Omisión de un
carácter, repetición de un carácter, y sustitución por vecino de teclado son,
por construcción, siempre una edición de distancia 1 — exactamente lo que
`_check_levenshtein` ya cubre antes de que cualquier check posterior tenga
oportunidad de correr. A diferencia de PyMongoose (que genera variantes y
compara por pertenencia a un set, sin fuerza bruta por defecto), en Nidhogg esos
tres generadores serían código inalcanzable. Se descartan.

Único generador nuevo, con valor real (cubre un caso de distancia 2 que
`_check_levenshtein` con `max_distance=1` no atrapa):

- `_check_pluralization` — añade/quita sufijo `s` o `es`. El caso `s` (distancia 1,
  ej. `boto3`→`boto3s`) normalmente ya lo captura Levenshtein primero y por tanto
  este check no llega a verlo; el caso `es` (distancia 2, ej. `box`→`boxes`) sí es
  nuevo. Se mantiene simple: un solo check que prueba ambos sufijos, sin
  reordenar el pipeline existente.

`_check_substitution` no se toca: los pares de un solo carácter (`1→l`, `0→o`) ya
son redundantes con Levenshtein-1 por el mismo motivo de arriba (preexistente,
no se corrige aquí por no formar parte del alcance), y no hay pares
multi-carácter adicionales con base real que justifiquen ampliar la tabla sin
inventarlos. El valor nuevo de este grupo viene de `pluralization` + las
señales de metadata/RDAP + la configurabilidad (threshold/confidence/exceptions)
+ el scoring de dos capas.

`check_typosquatting`:
1. Normaliza y descarta si el nombre ya está en el top.
2. Corre los checks en el orden actual (levenshtein, transposition, substitution,
   affix) + `_check_pluralization` al final.
3. Si hay match, comprueba `(candidato, objetivo)` contra `known_exceptions` del
   config — si coincide, descarta el finding (retorna `None`).
4. Asigna `confidence` según la tabla `[confidence]` del TOML, indexada por
   `TyposquatMethod` del finding.
5. Usa `max_distance` del TOML en vez de la constante `_MAX_LEVENSHTEIN` hardcodeada.

## Nuevo módulo: `enrichment/pypi_metadata.py`

Sin dependencias nuevas — `urllib.request` (stdlib), igual que `ssl_cert.py` y
`typosquat.update_top_packages`.

```python
@dataclass(frozen=True)
class PackageMetadata:
    name: str
    author_email: str | None
    maintainer_email: str | None
    summary: str | None
    keywords: tuple[str, ...]
    classifiers: tuple[str, ...]
    project_urls: tuple[tuple[str, str], ...]
    home_page: str | None
    first_release_at: datetime | None

@dataclass(frozen=True)
class DomainInfo:
    registered_at: datetime | None

def fetch_package_metadata(name: str, *, timeout: float = 10.0) -> PackageMetadata | None: ...
def fetch_domain_info(domain: str, *, timeout: float = 10.0) -> DomainInfo | None: ...

# Señales puras, sin red — portadas de PyMongoose signals.py, sin sklearn
# (similitud coseno vía collections.Counter, igual que el original):
def description_similarity(a: PackageMetadata, b: PackageMetadata) -> float: ...
def keyword_classifier_overlap(a: PackageMetadata, b: PackageMetadata) -> float: ...
def shared_repo_url(a: PackageMetadata, b: PackageMetadata) -> str | None: ...
def metadata_completeness(m: PackageMetadata) -> float: ...
def completeness_delta(a: PackageMetadata, b: PackageMetadata) -> float: ...
def domain_age_days(info: DomainInfo, reference_at: datetime) -> int | None: ...
def confidence_boost(*, ...) -> float: ...  # capado a 0.35, misma fórmula que PyMongoose

def enrich_typosquat(finding: TyposquatFinding) -> TyposquatFinding:
    """Descarga metadata del candidato y del objetivo, calcula boost, y devuelve
    una copia de *finding* con los campos de señales y adjusted_confidence
    rellenados. Cualquier fallo de red se captura y deja los campos en None
    (adjusted_confidence == confidence)."""
```

`fetch_package_metadata`/`fetch_domain_info` cachean por nombre/dominio dentro del
proceso (`functools.lru_cache` o dict simple) para no repetir llamadas en `--batch`.

## Integración (`cli.py`)

En `_analyse_one`, tras `analysis.typosquat = check_typosquatting(package_name)`:

```python
if analysis.typosquat is not None and typosquat_intel:
    from nidhogg.enrichment.pypi_metadata import enrich_typosquat
    analysis.typosquat = enrich_typosquat(analysis.typosquat)
```

Nuevo flag `--no-typosquat-intel` (opt-out, activo por defecto) en el parser,
propagado igual que `check_ssl`.

## Scoring (`scoring.py` + `scoring.toml`)

Nuevo campo en `[score.combo_bonuses]`: `typosquat_metadata_weight` (default `1.0`).

```python
if analysis.typosquat is not None:
    # bonus existente por distancia, sin cambios
    ...
    if analysis.typosquat.adjusted_confidence is not None:
        extra = analysis.typosquat.adjusted_confidence - analysis.typosquat.confidence
        bonus += extra * cfg.score.combo_bonuses.typosquat_metadata_weight
```

Sin enriquecimiento, `adjusted_confidence is None` → sin bonus extra, cero regresión
sobre el comportamiento/tests actuales.

## Testing

- `test_typosquat.py`: caso `_check_pluralization` (sufijo `es`, ej.
  `databas` → `databases`), test de `known_exceptions` filtrando un match real,
  test de `max_distance` configurable, test de `confidence` asignada por método.
- `test_typosquat_config.py`: carga de `typosquat.toml`, valores por defecto.
- `test_pypi_metadata.py`: señales puras sin red (casos con `PackageMetadata`
  construidos a mano). Fetch real mockeado con `unittest.mock.patch` sobre
  `_fetch_pypi_json`/`_fetch_rdap_json` internos (mismo patrón que `test_ssl_cert.py`).
- `test_scoring.py`: caso con `adjusted_confidence` set → bonus extra aplicado;
  caso sin enriquecer → bonus extra cero.
