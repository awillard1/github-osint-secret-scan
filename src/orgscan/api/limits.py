"""Request limits enforced before multipart parsing and bounded upload reads."""
from starlette.exceptions import HTTPException
from starlette.responses import JSONResponse

MAX_REQUEST_BYTES = 11_000_000
MAX_UPLOAD_BYTES = 10_000_000


class RequestBodyLimit:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)
        total = 0
        async def bounded_receive():
            nonlocal total
            message = await receive()
            total += len(message.get('body', b''))
            if total > MAX_REQUEST_BYTES:
                raise HTTPException(413, 'Request body exceeds the allowed size limit')
            return message
        try:
            await self.app(scope, bounded_receive, send)
        except HTTPException as exc:
            if exc.status_code != 413:
                raise
            await JSONResponse({'detail': exc.detail}, 413)(scope, receive, send)


async def read_upload(upload):
    chunks, total = [], 0
    try:
        while True:
            block = await upload.read(min(65536, MAX_UPLOAD_BYTES + 1 - total))
            if not block:
                return b''.join(chunks)
            total += len(block)
            if total > MAX_UPLOAD_BYTES:
                raise HTTPException(413, 'Uploaded artifact exceeds the allowed size limit')
            chunks.append(block)
    finally:
        await upload.close()
