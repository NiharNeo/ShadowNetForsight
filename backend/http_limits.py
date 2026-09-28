"""Bound request bodies before multipart parsing writes an unbounded upload."""
from starlette.exceptions import HTTPException
from starlette.responses import JSONResponse


class BodyLimitMiddleware:
    def __init__(self, app, upload_limit: int):
        self.app, self.upload_limit = app, upload_limit

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)
        upload = scope['path'] in {'/api/replays', '/api/calibration/profiles'}
        limit = self.upload_limit + 1024 * 1024 if upload else 2 * 1024 * 1024
        headers = dict(scope.get('headers', []))
        length = headers.get(b'content-length')
        if length is not None:
            try:
                size = int(length)
                if size < 0:
                    raise ValueError
            except ValueError:
                return await JSONResponse({'detail': 'Invalid Content-Length'}, 400)(scope, receive, send)
            if size > limit:
                return await JSONResponse({'detail': 'Request body too large'}, 413)(scope, receive, send)
        seen = 0

        async def bounded_receive():
            nonlocal seen
            message = await receive()
            if message['type'] == 'http.request':
                seen += len(message.get('body', b''))
                if seen > limit:
                    raise HTTPException(413, 'Request body too large')
            return message

        await self.app(scope, bounded_receive, send)
