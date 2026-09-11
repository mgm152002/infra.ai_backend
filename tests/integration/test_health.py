"""Tests for health and admin endpoints."""

import pytest
from unittest.mock import patch, MagicMock


class TestHealthEndpoints:
    """Test health check endpoints."""

    def test_admin_health_endpoint_exists(self):
        """Admin health endpoint should be defined."""
        # This tests that the route is registered
        from main import app

        routes = [route.path for route in app.routes if hasattr(route, "path")]
        assert "/admin/health" in routes

    def test_worker_queue_health_endpoint_exists(self):
        """Worker queue health endpoint should be defined."""
        from main import app

        routes = [route.path for route in app.routes if hasattr(route, "path")]
        assert "/worker/queue-health" in routes

    def test_admin_users_endpoint_exists(self):
        """Admin users endpoint should be defined."""
        from main import app

        routes = [route.path for route in app.routes if hasattr(route, "path")]
        assert "/admin/users" in routes
