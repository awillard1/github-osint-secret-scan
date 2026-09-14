"""Bounded file traversal and descriptor-relative no-symlink reads."""
import os
import stat
from pathlib import Path
from orgscan.scanners.base import ScannerExecutionError

MAX_ENTRIES = 100_000
MAX_FILE_BYTES = 1_000_000


def iter_files(target: Path):
    if target.is_symlink():
        return []
    if target.is_file():
        return [target]
    files, pending, count = [], [target], 0
    while pending:
        directory = pending.pop()
        if directory.is_symlink():
            continue
        with os.scandir(directory) as entries:
            for entry in entries:
                count += 1
                if count > MAX_ENTRIES:
                    raise ScannerExecutionError('Scanner traversal exceeded the entry limit')
                if entry.is_symlink() or entry.name == '.git':
                    continue
                if entry.is_dir(follow_symlinks=False):
                    pending.append(Path(entry.path))
                elif entry.is_file(follow_symlinks=False):
                    files.append(Path(entry.path))
    return sorted(files)


def read_text(path: Path, root: Path, max_bytes=MAX_FILE_BYTES):
    # Open every component without following symlinks, including ancestors of root.
    absolute = path.absolute()
    root = root.absolute()
    if not absolute.is_relative_to(root):
        raise OSError('File is outside the scan root')
    descriptors = []
    try:
        descriptor = os.open(absolute.anchor, os.O_RDONLY | os.O_DIRECTORY)
        descriptors.append(descriptor)
        for component in absolute.parts[1:-1]:
            descriptor = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            descriptors.append(descriptor)
        descriptor = os.open(absolute.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
        descriptors.append(descriptor)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > max_bytes:
            return ''
        blocks, total = [], 0
        while total <= max_bytes:
            block = os.read(descriptor, min(65536, max_bytes+1-total))
            if not block:
                break
            blocks.append(block)
            total += len(block)
        if total > max_bytes:
            return ''
        return b''.join(blocks).decode('utf-8')
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
