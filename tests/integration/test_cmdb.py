"""Tests for CMDB endpoints."""
import pytest
from unittest.mock import patch, MagicMock


class TestCMDBEndpoints:
    """Test CMDB CRUD endpoints."""

    def test_cmdb_endpoint_exists(self):
        """CMDB endpoint should be registered."""
        from main import app
        routes = [r.path for r in app.routes]
        assert "/cmdb" in routes

    def test_cmdb_by_service_endpoint_exists(self):
        """CMDB by-service endpoint should be registered."""
        from main import app
        routes = [r.path for r in app.routes]
        assert "/cmdb/by-service" in routes

    def test_cmdb_search_endpoint_exists(self):
        """CMDB search endpoint should be registered."""
        from main import app
        routes = [r.path for r in app.routes]
        assert any("cmdb/search" in r for r in routes)

    def test_services_endpoint_exists(self):
        """Services endpoint should be registered."""
        from main import app
        routes = [r.path for r in app.routes]
        assert "/services" in routes

    def test_services_hosts_endpoint_exists(self):
        """Services hosts endpoint should be registered."""
        from main import app
        routes = [r.path for r in app.routes]
        assert any("services" in r and "hosts" in r for r in routes)

    def test_upload_cmdb_endpoint_exists(self):
        """Upload CMDB endpoint should be registered."""
        from main import app
        routes = [r.path for r in app.routes]
        assert "/uploadCMDB" in routes
