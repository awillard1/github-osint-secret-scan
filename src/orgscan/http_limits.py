"""Bounded upstream reads with an absolute deadline and controlled size failures."""
import time
from orgscan.cancellation import check_cancelled


class ResponseTooLarge(ValueError):
    pass


def response_deadline(timeout):
    return time.monotonic() + timeout


def read_response(response, *, settings=None, deadline=None):
    limit = settings.http_response_max_bytes if settings else 2_000_000
    deadline = deadline if deadline is not None else response_deadline(settings.http_timeout_seconds if settings else 15)
    headers = getattr(response, 'headers', {})
    length = headers.get('Content-Length')
    if length is not None:
        try:
            size = int(length)
        except (TypeError, ValueError):
            size = None
        if size is not None and size > limit:
            raise ResponseTooLarge('HTTP response exceeds the allowed size limit')
    chunks, total = [], 0
    # HTTPResponse.read1 avoids waiting for a complete requested chunk while a
    # peer drips bytes. Its socket timeout is reduced to the remaining deadline.
    reader = getattr(response, 'read1', response.read)
    while True:
        check_cancelled()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('HTTP response deadline exceeded')
        sock = getattr(getattr(getattr(response, 'fp', None), 'raw', None), '_sock', None)
        if sock is not None:
            sock.settimeout(remaining)
        block = reader(min(65536, limit + 1 - total))
        if time.monotonic() > deadline:
            raise TimeoutError('HTTP response deadline exceeded')
        total += len(block)
        if total > limit:
            raise ResponseTooLarge('HTTP response exceeds the allowed size limit')
        if not block:
            return b''.join(chunks)
        chunks.append(block)
