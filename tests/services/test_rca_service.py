"""Tests for app.services.rca_service module."""

import pytest
from unittest.mock import patch, MagicMock


class TestRCAService:
    """Test RCA (Root Cause Analysis) service."""

    def test_rca_service_importable(self):
        """rca_service should be importable."""
        from app.services.rca_service import rca_service

        assert rca_service is not None

    def test_generate_rca_method_exists(self):
        """rca_service should have generate_rca method."""
        from app.services.rca_service import rca_service

        assert hasattr(rca_service, "generate_rca")

    def test_get_rca_method_exists(self):
        """rca_service should have get_rca method."""
        from app.services.rca_service import rca_service

        assert hasattr(rca_service, "get_rca")
