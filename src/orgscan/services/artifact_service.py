"""Bounded artifact preparation and transport-independent scan orchestration."""
from contextlib import contextmanager
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
import stat
import tarfile
import zipfile

from orgscan.archive_limits import tar_stream, check_zip_directory
from orgscan.config import Settings
from orgscan.repositories import Storage
from orgscan.services.scan_plan import resolve_scan_plan
from orgscan.services.scan_service import execute_plan, result_payload
from orgscan.services.target_service import resolve_asset_context

MAX_ARTIFACT_UPLOAD_BYTES = 10_000_000
MAX_ARTIFACT_EXTRACTED_BYTES = 25_000_000
MAX_ARTIFACT_EXTRACTED_FILES = 2_000


class ArtifactInputError(ValueError):
    """A safe, transport-independent artifact validation error."""

    def __init__(self, message: str, code: str = "invalid"):
        super().__init__(message)
        self.code = code

def _safe_artifact_name(filename: str | None) -> str:
    name = (Path(filename or "artifact.txt").name or "artifact.txt").replace("\x00", "")
    if name in ("", ".", ".."):
        raise ValueError("Invalid artifact filename")
    return name


def _archive_type(path: Path) -> str | None:
    name = path.name.lower()
    if name.endswith(".zip"):
        return "zip"
    if name.endswith(".tar") or name.endswith(".tar.gz") or name.endswith(".tgz"):
        return "tar"
    return None


def _safe_extract_destination(root: Path, member_name: str) -> Path:
    normalized = Path(member_name.lstrip("/"))
    destination = (root / normalized).resolve()
    if destination != root and root not in destination.parents:
        raise ValueError("Unsafe archive entry")
    return destination


def _extract_zip_artifact(artifact_path: Path, destination_root: Path, *, max_files=2000, max_bytes=25_000_000) -> int:
    file_count = 0
    total_bytes = 0
    check_zip_directory(artifact_path, max_files)
    with zipfile.ZipFile(artifact_path) as archive:
        for member in archive.infolist():
            mode = member.external_attr >> 16
            if mode and stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise ValueError("Uploaded archive contains unsupported special entries.")
            if member.is_dir():
                continue
            file_count += 1
            if file_count > max_files:
                raise ValueError("Uploaded archive contains too many files.")
            total_bytes += member.file_size
            if total_bytes > max_bytes:
                raise ValueError("Uploaded archive expands beyond the allowed size limit.")
            destination = _safe_extract_destination(destination_root, member.filename)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(archive.read(member))
    return file_count


@contextmanager
def prepare_artifact(content: bytes, filename: str | None, *, prefix: str = "orgscan-artifact-"):
    """Materialize one bounded input; remove it even when scanning fails."""
    name = _safe_artifact_name(filename)
    if not content:
        raise ArtifactInputError("Uploaded artifact is empty.")
    if len(content) > MAX_ARTIFACT_UPLOAD_BYTES:
        raise ArtifactInputError("Uploaded artifact exceeds the allowed size limit.", "too_large")
    with TemporaryDirectory(prefix=prefix) as temporary:
        root = Path(temporary)
        path = root / name
        path.write_bytes(content)
        kind = _archive_type(path)
        if kind is not None:
            expanded = root / "extracted"
            expanded.mkdir()
            try:
                count = (_extract_zip_artifact if kind == "zip" else _extract_tar_artifact)(
                    path, expanded, max_files=MAX_ARTIFACT_EXTRACTED_FILES,
                    max_bytes=MAX_ARTIFACT_EXTRACTED_BYTES,
                )
            except (tarfile.TarError, zipfile.BadZipFile, ValueError):
                # Archive parser messages may contain attacker-supplied names or data.
                raise ArtifactInputError("Invalid uploaded archive.") from None
            if count == 0:
                raise ArtifactInputError("Uploaded archive does not contain any regular files.")
            path = expanded
        yield path, name, kind


class ArtifactScanService:
    """Synchronous upload scan use case reusable by transport adapters."""

    def __init__(self, session_factory, settings: Settings):
        self.session_factory = session_factory
        self.settings = settings

    def scan_upload(self, *, filename: str | None, content: bytes,
                    scanner_name: str | None = None, profile: str | None = None,
                    organization: str | None = None, repository: str | None = None,
                    provider: str = "github") -> dict[str, object]:
        with prepare_artifact(content, filename) as (path, name, kind):
            with self.session_factory() as session:
                storage = Storage(session)
                organization_id, repository_id = resolve_asset_context(
                    storage, organization=organization, repository=repository, provider=provider,
                )
                plan = resolve_scan_plan(
                    target=str(path), target_type="artifact", profile=profile,
                    scanners=[scanner_name] if scanner_name else None, settings=self.settings,
                    organization_id=organization_id, repository_id=repository_id,
                )
                results = execute_plan(
                    storage, plan, settings=self.settings, target_label=name,
                    canonical_root=Path("/orgscan-artifacts") / sha256(name.encode()).hexdigest(),
                    command_line=f"api artifact scan {name} --scanners {','.join(plan.scanners)}",
                    parameters_json={"artifact_name": name, "artifact_kind": kind or "file",
                                     "extracted": kind is not None, "scanner": plan.scanners[0]},
                )
        return {**result_payload(results), "artifact_name": name, "extracted": kind is not None}


def _extract_tar_artifact(artifact_path: Path, destination_root: Path, *, max_files=2000, max_bytes=25_000_000) -> int:
    file_count = 0
    total_bytes = 0
    with tar_stream(artifact_path, max_bytes + max_files * 4096) as stream, tarfile.open(fileobj=stream, mode="r|") as archive:
        for entry_count, member in enumerate(archive, 1):
            if entry_count > max_files:
                raise ValueError("Uploaded archive contains too many entries")
            archive.members.clear()
            if member.isdir():
                continue
            if not member.isfile():
                raise ValueError("Uploaded archive contains unsupported special entries.")
            file_count += 1
            if file_count > max_files:
                raise ValueError("Uploaded archive contains too many files.")
            total_bytes += member.size
            if total_bytes > max_bytes:
                raise ValueError("Uploaded archive expands beyond the allowed size limit.")
            extracted = archive.extractfile(member)
            if extracted is None:
                continue
            destination = _safe_extract_destination(destination_root, member.name)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(extracted.read())
    return file_count
