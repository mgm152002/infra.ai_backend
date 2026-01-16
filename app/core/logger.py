import logging
import json
import sys
from datetime import datetime
from logging.handlers import RotatingFileHandler
from typing import Any, Dict, Optional

class JSONFormatter(logging.Formatter):
    """
    Formatter that outputs JSON strings after parsing the LogRecord.
    """
    def format(self, record: logging.LogRecord) -> str:
        message = record.getMessage()
        
        log_record = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": message,
            "module": record.module,
            "func": record.funcName,
            "lineno": record.lineno,
        }

        # Add any extra attributes passed in extra={}
        # We explicitly look for 'props' which is our convention for structured data
        if hasattr(record, "props"):
            log_record.update(record.props)

        # Handle exceptions
        if record.exc_info:
            log_record["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_record)

def setup_logger(name: str = "infra_backend", log_file: str = "infra_backend.log", level: str = "INFO"):
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Clear existing handlers
    if logger.hasHandlers():
        logger.handlers.clear()

    formatter = JSONFormatter()

    # Console Handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    # File Handler
    if log_file:
        fh = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5)
        fh.setFormatter(formatter)
        logger.addHandler(fh)

    return logger

# Global logger instance
logger = setup_logger()

def audit_log(
    action: str, 
    user_id: Any, 
    resource: str, 
    details: Optional[Dict[str, Any]] = None, 
    status: str = "success",
    level: str = "INFO"
):
    """
    Helper to log audit events in a standardized way.
    """
    props = {
        "event_type": "audit",
        "action": action,
        "user_id": str(user_id),
        "resource": resource,
        "status": status,
    }
    if details:
        props["details"] = details
        
    msg = f"Audit: User {user_id} performed {action} on {resource} ({status})"
    
    if level.upper() == "INFO":
        logger.info(msg, extra={"props": props})
    elif level.upper() == "WARNING":
        logger.warning(msg, extra={"props": props})
    elif level.upper() == "ERROR":
        logger.error(msg, extra={"props": props})
    else:
        logger.info(msg, extra={"props": props})

def make_ctx_logger(base_logger, incident=None, instance=None, user=None):
    """
    Create a context-aware logger adapter.
    """
    prefix = f"[incident={incident or 'unknown'}] [instance={instance or 'unknown'}] [user={user or 'unknown'}]"
    class Ctx:
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
    return Ctx()
