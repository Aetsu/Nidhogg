# Fetch de paquete puntual + Monitor de altas nuevas en PyPI — Diseño

**Fecha:** 2026-07-08
**Grupo:** 3 de 3 (usa los campos de [[2026-07-08-typosquat-metadata-signals-design]]
y el flag `--history-dir` de [[2026-07-08-output-persistence-design]])

## Objetivo

Dar a Nidhogg capacidad propia de descargar paquetes de PyPI para analizarlos, en
dos modos: un paquete puntual (`fetch`) y vigilancia continua de altas nuevas
(`monitor`, con descarga + análisis de todos los paquetes nuevos publicados).

## Cambio de alcance respecto a CLAUDE.md

El CLAUDE.md actual dice que el downloader es "un componente externo, no parte de
este proyecto" y que Nidhogg solo recibe "carpetas ya extraídas". Esto sigue siendo
así para el flujo batch normal (`nidhogg analyze`, `nidhogg analyze --batch`), que no
cambia. `fetch` y `monitor` añaden una capacidad nueva y aislada: un fetcher propio,
mínimo, específico para analizar altas de PyPI bajo demanda o en vigilancia continua
— no modifica ni depende del downloader externo existente. Se actualiza el CLAUDE.md
para reflejar esta distinción (ver sección final).

## CLI: ruptura a subcomandos

Se reestructura `cli.py` de un único comando plano a subcomandos explícitos:

```
nidhogg analyze <carpeta> [flags actuales: --json --output --benign-domains
                            --check-ssl --verbose --batch --update-top-packages
                            --no-typosquat-intel --history-dir]
nidhogg fetch <nombre> [--version X] [--no-check-urls] [--no-check-typosquat]
                        [--keep-download [DIR]] [--json] [--output PATH]
                        [--history-dir PATH]
nidhogg monitor [--interval 300] [--index-file PATH] [--concurrency 4]
                 [--no-check-urls] [--no-check-typosquat] [--keep-download]
                 [--json] [--history-dir PATH]
```

Cambio incompatible deliberado: `nidhogg <carpeta>` deja de funcionar, hay que usar
`nidhogg analyze <carpeta>`. Coherente con la convención propia del proyecto de no
introducir parches de compatibilidad retroactiva. Se actualiza el `README`/`--help`.

`argparse` con `add_subparsers(dest="command", required=True)`.

## Módulo nuevo: `nidhogg/fetching/pypi_fetch.py`

Sin dependencias nuevas — `urllib.request`, `tarfile`, `zipfile`, `tempfile`, `shutil`
(todo stdlib).

```python
@dataclass(frozen=True)
class DownloadInfo:
    url: str
    filename: str
    packagetype: str  # "sdist" | "bdist_wheel"

def resolve_download_info(name: str, version: str | None = None, *, timeout: float = 10.0) -> DownloadInfo:
    """Consulta la PyPI JSON API. Prioriza el primer archivo con
    packagetype == 'sdist' de la versión resuelta; si no hay sdist, cae al
    primer 'bdist_wheel'. Lanza PackageReadError si el nombre no existe."""

def _safe_extract_tar(archive_path: Path, dest: Path) -> None:
    """tarfile.open(...).extractall(dest, filter="data") — filtro estándar de
    Python 3.12+ que rechaza symlinks/hardlinks fuera de dest y paths absolutos."""

def _safe_extract_zip(archive_path: Path, dest: Path) -> None:
    """zipfile.ZipFile — valida cada member.filename antes de extraer: rechaza
    rutas absolutas y componentes '..' (zipfile no tiene filter= nativo)."""

def download_and_extract(name: str, version: str | None = None) -> Path:
    """Descarga a un fichero temporal, extrae con la función segura según
    extensión, y devuelve la carpeta con el contenido. El caller es
    responsable de limpiarla (ver fetched_package)."""

@contextmanager
def fetched_package(
    name: str, version: str | None = None, *, keep: bool = False, keep_dir: Path | None = None
) -> Iterator[Path]:
    """Yield la carpeta extraída. Si keep es False (default), la borra al
    salir del bloque (shutil.rmtree). Si keep es True, la deja en su sitio
    (o la mueve a keep_dir si se indica) y loggea la ruta final."""
```

## Refactor `cli.py::_analyse_one`

Nuevos parámetros `run_url_analysis: bool = True`, `run_typosquat: bool = True`:

```python
def _analyse_one(
    package_path: Path,
    *,
    benign_domains_path: Path | None = None,
    check_ssl: bool = False,
    package_name: str | None = None,
    typosquat_intel: bool = True,
    run_url_analysis: bool = True,
    run_typosquat: bool = True,
) -> tuple[PackageAnalysis, Verdict] | None:
    ...
    if run_url_analysis:
        analysis = analyze_package(package_path)
        # aggregate + check_ssl como hoy
    else:
        analysis = PackageAnalysis(name=package_name or package_path.name, path=package_path)

    if run_typosquat and package_name is not None:
        analysis.typosquat = check_typosquatting(package_name)
        if analysis.typosquat is not None and typosquat_intel:
            analysis.typosquat = enrich_typosquat(analysis.typosquat)
    ...
```

`analyze` sigue invocando con ambos en `True` (comportamiento actual intacto).

## Subcomando `fetch`

```python
def _run_fetch(name, version, *, check_urls, check_typosquat, keep_download, ...) -> int:
    with fetched_package(name, version, keep=keep_download is not False, keep_dir=keep_download) as path:
        result = _analyse_one(
            path,
            package_name=name,
            run_url_analysis=check_urls,
            run_typosquat=check_typosquat,
        )
    ...  # imprime igual que _run_analyze
```

Errores de red/descarga (`PackageReadError` o excepción de `pypi_fetch`) se
imprimen a stderr y devuelven `_EXIT_ERROR`, igual patrón que el resto de la CLI.

## Subcomando `monitor`

Reutiliza el patrón `ChangelogClient` de PyMongoose (stdlib `xmlrpc.client`,
`SafeTransport` con timeout por instancia — sin `socket.setdefaulttimeout` global):

```python
# nidhogg/fetching/changelog.py
class ChangelogClient:
    def current_serial(self) -> int: ...
    def entries_since(self, serial: int) -> list[ChangelogEntry]: ...

@dataclass(frozen=True)
class ChangelogEntry:
    name: str
    version: str
    timestamp: int
    action: str
    serial: int

    @property
    def is_new_project(self) -> bool:
        return self.action == "create"
```

Índice persistido:

```python
# nidhogg/fetching/monitor_state.py
@dataclass(frozen=True)
class MonitorState:
    last_serial: int

def load_state(index_file: Path) -> MonitorState | None: ...
def save_state(index_file: Path, state: MonitorState) -> None: ...
```

Default `index_file`: `Path.home() / ".cache" / "nidhogg" / "monitor_state.json"`.

Bucle principal:

```python
def _run_monitor(*, interval, index_file, concurrency, check_urls, check_typosquat, ...) -> int:
    client = ChangelogClient()
    state = load_state(index_file)
    last_serial = state.last_serial if state else client.current_serial()

    try:
        while True:
            current = client.current_serial()
            entries = [e for e in client.entries_since(last_serial) if e.is_new_project]

            with ThreadPoolExecutor(max_workers=concurrency) as pool:
                futures = {
                    pool.submit(_fetch_and_analyse_one, e.name, check_urls, check_typosquat): e
                    for e in entries
                }
                for future in as_completed(futures):
                    entry = futures[future]
                    try:
                        result = future.result()
                    except Exception as exc:  # noqa: BLE001 — un paquete no debe tumbar el monitor
                        logger.error("Fallo analizando {}: {}", entry.name, exc)
                        continue
                    _print_or_store(result)  # + history si --history-dir

            last_serial = current
            save_state(index_file, MonitorState(last_serial=last_serial))
            time.sleep(interval)
    except KeyboardInterrupt:
        logger.info("Monitor detenido en serial {}", last_serial)
    return 0
```

Puntos clave:
- `save_state` se llama **cada iteración**, no solo al salir — si el proceso muere
  a mitad, se pierde como mucho un intervalo, no todo el histórico.
- Sin `--index-file` previo, arranca desde `current_serial()` (no procesa el
  historial completo de PyPI en el primer arranque).
- `check_urls`/`check_typosquat` ambos `True` por defecto — analiza toda alta
  nueva con el pipeline completo, sin prefiltro de nombre (decisión explícita:
  cobertura sobre coste).
- `--keep-download` en monitor conserva cada carpeta descargada bajo un
  subdirectorio por paquete (necesita ruta base, no un único `keep_dir`).

## CLAUDE.md — actualización

Añadir a "Contexto del proyecto":

> Además del flujo principal (carpetas ya extraídas por un downloader externo),
> Nidhogg incluye un fetcher propio y aislado (`nidhogg/fetching/`) para dos casos
> de uso específicos: analizar un paquete puntual bajo demanda (`nidhogg fetch`) y
> vigilar altas nuevas en PyPI en tiempo real (`nidhogg monitor`). Este fetcher no
> sustituye ni depende del downloader externo del flujo batch.

Añadir `fetching/` al diagrama de arquitectura, y documentar los 3 subcomandos en
la sección de arquitectura/CLI.

## Testing

- `test_pypi_fetch.py`: `resolve_download_info` con payload JSON mockeado (prioriza
  sdist), extracción seguro con fixture tar.gz que contiene un miembro con
  `../../etc/passwd` → debe rechazarse; mismo caso con zip.
- `test_changelog.py`: `ChangelogClient` con `xmlrpc.client.ServerProxy` mockeado.
- `test_monitor_state.py`: round-trip `save_state`/`load_state`, `None` si no existe.
- `test_cli.py` (nuevo, cierra el gap detectado en la comparación inicial):
  subcomandos `analyze`/`fetch`/`monitor` con `unittest.mock.patch` sobre las
  funciones de red/fetch, cubriendo exit codes y flags principales.
