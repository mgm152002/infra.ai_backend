import asyncio
import time
import uuid
from starlette.types import ASGIApp, Message, Receive, Scope, Send
from app.core.logger import logger

class RequestLoggingMiddleware:
    """
    Streaming-safe request logger.
    Uses raw ASGI interface instead of BaseHTTPMiddleware, which can emit noisy
    CancelledError traces for SSE/streaming responses on disconnect/shutdown.
    """

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "UNKNOWN")
        path = scope.get("path", "")
        request_id = None
        for header_key, header_value in scope.get("headers", []):
            if header_key.decode("latin-1").lower() == "x-request-id":
                request_id = header_value.decode("latin-1")
                break
        request_id = request_id or str(uuid.uuid4())
        start_time = time.time()
        status_code = 500
        response_started = False

        logger.info(
            f"Request started: {method} {path}",
            extra={"props": {"request_id": request_id, "method": method, "path": path}},
        )

        async def send_wrapper(message: Message) -> None:
            nonlocal status_code, response_started
            if message.get("type") == "http.response.start":
                response_started = True
                status_code = int(message.get("status", 200))
                headers = list(message.get("headers") or [])
                headers.append((b"x-request-id", request_id.encode("latin-1")))
                message["headers"] = headers
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
            process_time = time.time() - start_time

            logger.info(
                "Request completed",
                extra={
                    "props": {
                        "request_id": request_id,
                        "status_code": status_code if response_started else 500,
                        "latency_ms": round(process_time * 1000, 2),
                    }
                },
            )
        except asyncio.CancelledError:
            process_time = time.time() - start_time
            logger.info(
                "Request cancelled",
                extra={
                    "props": {
                        "request_id": request_id,
                        "status_code": status_code if response_started else 499,
                        "latency_ms": round(process_time * 1000, 2),
                        "path": path,
                    }
                },
            )
            # Propagate cancellation; this is expected for client disconnect/shutdown.
            raise
        except Exception as e:
            process_time = time.time() - start_time
            logger.error(
                f"Request failed: {str(e)}",
                extra={
                    "props": {
                        "request_id": request_id,
                        "error": str(e),
                        "latency_ms": round(process_time * 1000, 2),
                    }
                },
            )
            raise
