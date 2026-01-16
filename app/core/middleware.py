import time
import uuid
from typing import Callable
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from app.core.logger import logger

class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        start_time = time.time()
        
        # Create a context-aware logger adapter (simple version for now)
        # Ideally, we used contextvars, but for simplicity we log with extra props here.
        
        logger.info(f"Request started: {request.method} {request.url.path}", 
                    extra={"props": {"request_id": request_id, "method": request.method, "path": request.url.path}})
        
        try:
            response = await call_next(request)
            process_time = time.time() - start_time
            
            logger.info(f"Request completed", 
                        extra={"props": {
                            "request_id": request_id, 
                            "status_code": response.status_code, 
                            "latency_ms": round(process_time * 1000, 2)
                        }})
            
            response.headers["X-Request-ID"] = request_id
            return response
            
        except Exception as e:
            process_time = time.time() - start_time
            logger.error(f"Request failed: {str(e)}", 
                         extra={"props": {
                             "request_id": request_id, 
                             "error": str(e),
                             "latency_ms": round(process_time * 1000, 2)
                        }})
            raise e
