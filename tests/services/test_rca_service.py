"""Tests for app.services.rca_service module."""
import sys
from unittest.mock import MagicMock, patch

import pytest

# Mock langchain_openai before importing rca_service
_langchain_mock = MagicMock()
_sys_patch = patch.dict("sys.modules", {"langchain_openai": _langchain_mock})
_sys_patch.start()

# Also mock ChatOpenAI specifically
_langchain_mock.ChatOpenAI = MagicMock

# Now safe to import
try:
    from app.services.rca_service import rca_service

    RCA_SERVICE_AVAILABLE = True
except ImportError:
    RCA_SERVICE_AVAILABLE = False


class TestRCAService:
    """Test RCA (Root Cause Analysis) service."""

    def test_rca_service_importable(self):
        """rca_service should be importable."""
        assert RCA_SERVICE_AVAILABLE, "rca_service could not be imported"
        assert rca_service is not None

    @pytest.mark.skipif(not RCA_SERVICE_AVAILABLE, reason="rca_service not available")
    def test_generate_rca_method_exists(self):
        """rca_service should have generate_rca method."""
        assert hasattr(rca_service, "generate_rca")

    @pytest.mark.skipif(not RCA_SERVICE_AVAILABLE, reason="rca_service not available")
    def test_get_rca_method_exists(self):
        """rca_service should have get_rca method."""
        assert hasattr(rca_service, "get_rca")
