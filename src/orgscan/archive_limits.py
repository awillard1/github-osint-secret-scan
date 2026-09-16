"""Bound archive metadata before standard-library allocation."""
import gzip
import struct
from contextlib import contextmanager


class LimitedReader:
    def __init__(self, stream, limit):
        self.stream, self.remaining = stream, limit
    def read(self, size=-1):
        data = self.stream.read(min(size if size >= 0 else self.remaining+1, self.remaining+1))
        self.remaining -= len(data)
        if self.remaining < 0:
            raise ValueError('Archive stream exceeds the allowed size limit')
        return data


@contextmanager
def tar_stream(path, limit):
    with open(path, 'rb') as raw:
        if raw.read(2) == b'\x1f\x8b':
            raw.seek(0)
            with gzip.GzipFile(fileobj=raw) as decoded:
                yield LimitedReader(decoded, limit)
        else:
            raw.seek(0)
            yield LimitedReader(raw, limit)


def check_zip_directory(path, max_entries):
    with open(path, 'rb') as stream:
        stream.seek(0, 2)
        size = stream.tell()
        stream.seek(max(0, size-65557))
        tail = stream.read(65557)
        index = tail.rfind(b'PK\x05\x06')
        if index < 0 or index+22 > len(tail):
            raise ValueError('Invalid ZIP directory')
        _, disk, directory_disk, entries_disk, entries, length, offset, comment = struct.unpack('<4s4H2LH',tail[index:index+22])
        if disk or directory_disk or entries != entries_disk or entries > max_entries or offset+length > size or length > 2_000_000:
            raise ValueError('ZIP directory exceeds supported limits')
        stream.seek(offset)
        consumed = count = 0
        while consumed < length:
            header = stream.read(46)
            if len(header) != 46 or header[:4] != b'PK\x01\x02':
                raise ValueError('Invalid ZIP directory entry')
            count += 1
            if count > max_entries:
                raise ValueError('Uploaded archive contains too many entries')
            extra = sum(struct.unpack('<3H', header[28:34]))
            consumed += 46+extra
            if consumed > length:
                raise ValueError('Invalid ZIP directory size')
            stream.seek(extra, 1)
        if count != entries:
            raise ValueError('Invalid ZIP directory count')
