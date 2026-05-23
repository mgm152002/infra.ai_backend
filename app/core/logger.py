import json
import logging
import sys
from datetime import UTC, datetime
from logging.handlers import RotatingFileHandler
from typing import Any, Dict, Optional


class JSONFormatter(logging.Formatter):
    """Serialize log records into a compact JSON payload."""

    def format(self, record: logging.LogRecord) -> str:
        message = record.getMessage()
        log_record = {
            "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "level": record.levelname,
            "logger": record.name,
            "message": message,
            "module": record.module,
            "func": record.funcName,
            "lineno": record.lineno,
        }

        if hasattr(record, "props"):
            log_record.update(record.props)

        if record.exc_info:
            log_record["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_record)


def setup_logger(
    name: str = "infra_backend",
    log_file: str = "infra_backend.log",
    level: str = "INFO",
):
    """Create a logger with JSON output for stdout and optional file rotation."""

    configured_logger = logging.getLogger(name)
    configured_logger.setLevel(level)

    if configured_logger.hasHandlers():
        configured_logger.handlers.clear()

    formatter = JSONFormatter()

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    configured_logger.addHandler(console_handler)

    if log_file:
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,
            backupCount=5,
        )
        file_handler.setFormatter(formatter)
        configured_logger.addHandler(file_handler)

    return configured_logger


logger = setup_logger()


def audit_log(
    action: str,
    user_id: Any,
    resource: str,
    details: Optional[Dict[str, Any]] = None,
    status: str = "success",
    level: str = "INFO",
):
    """Log audit events with a consistent structure."""

    props = {
        "event_type": "audit",
        "action": action,
        "user_id": str(user_id),
        "resource": resource,
        "status": status,
    }
    if details:
        props["details"] = details

    message = f"Audit: User {user_id} performed {action} on {resource} ({status})"

    if level.upper() == "WARNING":
        logger.warning(message, extra={"props": props})
    elif level.upper() == "ERROR":
        logger.error(message, extra={"props": props})
    else:
        logger.info(message, extra={"props": props})


def make_ctx_logger(base_logger, incident=None, instance=None, user=None):
    """Create a lightweight context-aware logger wrapper."""

    prefix = (
        f"[incident={incident or 'unknown'}] "
        f"[instance={instance or 'unknown'}] "
        f"[user={user or 'unknown'}]"
    )

    class CtxLogger:
        def info(self, msg, *args, **kwargs):
            base_logger.info(f"{prefix} {msg}", *args, **kwargs)

        def debug(self, msg, *args, **kwargs):
            base_logger.debug(f"{prefix} {msg}", *args, **kwargs)

        def warning(self, msg, *args, **kwargs):
            base_logger.warning(f"{prefix} {msg}", *args, **kwargs)

        def error(self, msg, *args, **kwargs):
            base_logger.error(f"{prefix} {msg}", *args, **kwargs)

        def exception(self, msg, *args, **kwargs):
            base_logger.exception(f"{prefix} {msg}", *args, **kwargs)

    return CtxLogger()
