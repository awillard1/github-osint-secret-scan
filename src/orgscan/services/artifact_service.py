"""Shared bounded archive preparation for standalone and assessment scans."""
from pathlib import Path
import tarfile
import zipfile
from orgscan.archive_limits import tar_stream, check_zip_directory

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
