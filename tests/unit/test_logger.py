"""Tests for app.core.logger module."""

import pytest
import logging
import json


class TestLogger:
    """Test JSON structured logger."""

    def test_logger_is_importable(self):
        """Logger should be importable from app.core.logger."""
        from app.core.logger import logger

        assert logger is not None

    def test_logger_has_handlers(self):
        """Logger should have at least one handler configured."""
        from app.core.logger import logger

        assert len(logger.handlers) > 0

    def test_logger_is_logging_logger(self):
        """Logger should be a standard logging.Logger instance."""
        from app.core.logger import logger

        assert isinstance(logger, logging.Logger)

    def test_make_ctx_logger_function_exists(self):
        """make_ctx_logger should be importable."""
        from app.core.logger import make_ctx_logger

        assert callable(make_ctx_logger)

    def test_logger_can_log_info(self, caplog):
        """Logger should be able to log info messages."""
        from app.core.logger import logger

        with caplog.at_level(logging.INFO):
            logger.info("Test info message")

        assert "Test info message" in caplog.text

    def test_logger_can_log_error(self, caplog):
        """Logger should be able to log error messages."""
        from app.core.logger import logger

        with caplog.at_level(logging.ERROR):
            logger.error("Test error message")

        assert "Test error message" in caplog.text
