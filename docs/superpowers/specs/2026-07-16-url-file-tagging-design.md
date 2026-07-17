# Sistema de etiquetado de archivos y URLs

**Fecha:** 2026-07-16
**Estado:** Aprobado — pendiente de plan de implementación

## Objetivo

Introducir un sistema de etiquetado en dos niveles durante el análisis de un
paquete: etiquetas de **archivo** (dónde vive una URL: README, test, docs,
packaging…) y etiquetas de **URL** (cómo se detectó y qué amenaza de dominio
presenta). Las etiquetas sustituyen a los mecanismos de señalización previos
(`DetectionMethod`, `DomainThreatCategory`) y sientan la base para un futuro
sistema de scoring que pondere cada etiqueta.

## Decisiones de diseño

- **Dos niveles de etiquetado** (archivo + URL), tipados como dos enums
  distintos. Los conjuntos (`set`) deduplican gratis.
- **Absorber el sistema anterior**: `DetectionMethod` y `DomainThreatCategory`
  se pliegan en etiquetas. `AnalysisLayer` y el enriquecimiento SSL
  (`cert_issuer`, `ssl_cert.py`) se conservan como metadatos.
- **Granularidad del método**: cada técnica de extracción es su propia etiqueta
  (`via_base64`, `via_concat`, `via_fstring`, `via_scope`), sin colapsar en un
  único `obfuscated` — no se pierde información y el score futuro puede ponderar
  cada técnica por separado.
- **Cobertura de archivos**: se amplía el walker a una lista blanca de tipos de
  texto (`.py` + `README*`, `*.md`, `*.rst`, `*.txt`, `*.cfg`, `*.toml`), no un
  crawl de todo el sistema de ficheros. Layer1 (regex) corre sobre todos los
  archivos de texto; Layer2 (AST) solo sobre `.py`.

## Modelo de datos (`core/models.py`)

**Se conserva:** `AnalysisLayer`, el campo `layer`, `cert_issuer` y todo el
enriquecimiento SSL.

**Se elimina:** `DetectionMethod`, `DomainThreatCategory`, el campo `method` y
el campo `domain_threat`.

### Nuevos enums

```python
class FileTag(enum.Enum):
    README = "readme"              # README*
    DOCS = "docs"                  # *.md, *.rst, *.txt, docs/ en la ruta
    TEST = "test"                  # test_*, *_test.py, tests/ o test/ en la ruta
    EXAMPLE = "example"            # example*/sample* en nombre o ruta
    PACKAGING = "packaging"        # setup.py, setup.cfg, pyproject.toml, MANIFEST.in
    INIT = "init"                  # __init__.py
    ENTRYPOINT = "entrypoint"      # __main__.py
    DOTFILE = "dotfile"            # cualquier parte de la ruta empieza por "."
    DYNAMIC_EXEC = "dynamic_exec"  # archivo .py usa eval/exec/compile


class UrlTag(enum.Enum):
    # método de extracción (antes DetectionMethod; LITERAL no genera etiqueta)
    VIA_BASE64 = "via_base64"
    VIA_CONCAT = "via_concat"
    VIA_FSTRING = "via_fstring"
    VIA_SCOPE = "via_scope"
    RAW_IP = "raw_ip"              # antes DetectionMethod.IP + DomainThreatCategory.RAW_IP
    # amenaza de dominio (antes DomainThreatCategory)
    SHORTENER = "shortener"
    TUNNELING = "tunneling"
    EXFILTRATION = "exfiltration"
    IP_RECON = "ip_recon"
    MALWARE_HOSTING = "malware_hosting"
    SUSPICIOUS_TLD = "suspicious_tld"
```

### Contenedores en dos niveles

```python
@dataclass
class UrlFinding:
    value: str
    filepath: Path
    lineno: int
    layer: AnalysisLayer
    tags: set[UrlTag] = field(default_factory=set)
    cert_issuer: str | None = None


@dataclass
class FileAnalysis:
    filepath: Path
    tags: set[FileTag] = field(default_factory=set)
    findings: list[UrlFinding] = field(default_factory=list)


@dataclass
class PackageAnalysis:
    name: str
    path: Path
    files: list[FileAnalysis] = field(default_factory=list)

    @property
    def findings(self) -> list[UrlFinding]:
        """Aplana los findings de todos los archivos.

        Reduce el impacto en los consumidores que iteraban sobre
        ``PackageAnalysis.findings`` en el modelo plano anterior.
        """
        return [f for fa in self.files for f in fa.findings]
```

## Productores de etiquetas

Todos son funciones puras (entrada → salida, sin estado global).

### Etiquetas de archivo — `analysis/file_classifier.py` (nuevo)

```python
def classify_file(path: Path, root: Path) -> set[FileTag]:
    """Etiquetas basadas en ruta/nombre. No lee contenido."""
```

Reglas sobre la ruta relativa a la raíz del paquete, case-insensitive:

| Condición | Etiqueta |
|-----------|----------|
| nombre empieza por `README` | `README` |
| sufijo en `.md`/`.rst`/`.txt`, o `docs/` en la ruta | `DOCS` |
| `test_*`, `*_test.py`, o `tests/`/`test/` en la ruta | `TEST` |
| `example*`/`sample*` en nombre o ruta | `EXAMPLE` |
| `setup.py`, `setup.cfg`, `pyproject.toml`, `MANIFEST.in` | `PACKAGING` |
| `__init__.py` | `INIT` |
| `__main__.py` | `ENTRYPOINT` |
| cualquier parte de la ruta empieza por `.` | `DOTFILE` |

Un archivo puede acumular varias etiquetas (p. ej. `tests/__init__.py` →
`TEST` + `INIT`). `DYNAMIC_EXEC` **no** se calcula aquí (requiere contenido).

### Etiquetas de método — en construcción del finding

- Layer1: URL literal → sin etiqueta de método. IP → `RAW_IP`.
- Layer2: mapea su técnica de detección → `VIA_BASE64` / `VIA_CONCAT` /
  `VIA_FSTRING` / `VIA_SCOPE`. Literal en AST → sin etiqueta.
- Sustituye el antiguo argumento `method=` por `tags={...}` en cada punto de
  construcción de `UrlFinding`.

### `DYNAMIC_EXEC` — en Layer2

`extract_urls_ast` ya recorre el AST. Se añade la detección de llamadas
`ast.Call` a `eval`/`exec`/`compile` y la firma pasa a devolver
`(findings, uses_dynamic_exec: bool)`. El walker convierte ese booleano en la
`FileTag.DYNAMIC_EXEC` del `FileAnalysis`.

### Etiquetas de dominio — `analysis/domain_classifier.py`

`classify_domain(url) -> set[UrlTag]` (antes `-> DomainThreatCategory | None`).
Misma lógica y mismas listas de dominios (`data/`); devuelve el subconjunto de
`UrlTag` de amenaza (`SHORTENER`, `TUNNELING`, `EXFILTRATION`, `IP_RECON`,
`MALWARE_HOSTING`, `SUSPICIOUS_TLD`). Se aplica en el aggregator.

## Pipeline

```
walker:
  files = recolectar lista_blanca(.py + README*/*.md/*.rst/*.txt/*.cfg/*.toml)
  para cada archivo:
    ftags = classify_file(path, root)
    findings_layer1 = extract_urls_regex(...)        # todos los de texto
    si es .py:
      findings_layer2, dyn_exec = extract_urls_ast(...)
      si dyn_exec: ftags.add(FileTag.DYNAMIC_EXEC)
    FileAnalysis(path, ftags, findings_layer1 + findings_layer2)
  -> aggregator

aggregator:
  dedup de findings (por archivo: clave value+lineno; fusiona los set de tags
    en caso de colisión)
  adjunta UrlTags de dominio vía classify_domain(value)

enrichment (ssl): sin cambios; fija cert_issuer
```

Layer1 pasa a ejecutarse también sobre texto no-`.py` (URLs en README). La
extracción de IPs sigue siendo solo para `.py`: su regex de contexto de red
(`connect(`, `requests.get(`…) tiene forma de llamada Python, así que las IPs
sueltas en README se ignoran deliberadamente.

## Salida

- `output/writer.py` (JSON): objetos por archivo —
  `{filepath, tags: [filetags], findings: [{value, lineno, layer, tags: [urltags], cert_issuer}]}`.
  Se eliminan las claves `method` y `domain_threat`.
- `output/renderer.py` (rich): agrupa findings por archivo, muestra las
  etiquetas de archivo como badges y las de URL como chips por finding.
- `output/history.py` (JSONL append-only): refleja la nueva forma. Las líneas
  antiguas siguen siendo legibles; no hay migración hacia atrás.

## Limpieza del sistema anterior

- Eliminar los enums `DetectionMethod` y `DomainThreatCategory`.
- Eliminar los campos `method` y `domain_threat`.
- `domain_classifier.py` devuelve `set[UrlTag]` y deja de importar el enum
  eliminado.
- Barrido con grep: ninguna referencia a los enums/campos eliminados sobrevive.

## Testing

**Nuevos:**
- `tests/test_file_classifier.py`: cada regla de `FileTag`, casos multi-etiqueta,
  dotfile.
- Test de detección de `eval`/`exec`/`compile` en `tests/test_layer2_ast.py`.

**Actualizados:**
- Tests de layer1/layer2: `method=` → `tags=`; asserts sobre los conjuntos de
  etiquetas.
- Tests del aggregator: adjuntado de etiquetas de dominio y fusión de conjuntos
  en colisión de dedup.
- Tests de writer/renderer/history: nueva forma de salida.

**Fixtures:**
- Añadir un `README.md` de fixture con una URL.
- Los fixtures de URL ofuscada ya existen.

## Notas de migración

Cambio incompatible en el esquema JSON/JSONL. No hay consumidores fuera del
repositorio (el downloader es externo y la salida es el estado terminal del
pipeline), por lo que no se añade capa de compatibilidad.
