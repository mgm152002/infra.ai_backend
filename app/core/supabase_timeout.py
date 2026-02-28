import os
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from typing import Callable, TypeVar

from app.core.logger import logger

T = TypeVar("T")

_QUERY_TIMEOUT_S = float(os.getenv("SUPABASE_QUERY_TIMEOUT_S", "120"))
_EXECUTOR = ThreadPoolExecutor(max_workers=int(os.getenv("SUPABASE_TIMEOUT_WORKERS", "16")))


class SupabaseTimeoutError(TimeoutError):
    pass


def run_supabase_with_timeout(
    operation: Callable[[], T],
    *,
    timeout_s: float = _QUERY_TIMEOUT_S,
    operation_name: str = "supabase_query",
) -> T:
    """
    Execute a blocking Supabase call in a worker thread with a hard timeout.
    Prevents request handlers from hanging forever when network/DB is slow.
    """
    future = _EXECUTOR.submit(operation)
    try:
        return future.result(timeout=timeout_s)
    except FuturesTimeoutError as e:
        future.cancel()
        msg = f"{operation_name} timed out after {timeout_s}s"
        logger.error(msg)
        raise SupabaseTimeoutError(msg) from e
