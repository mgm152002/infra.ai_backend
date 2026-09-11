"""Tests for health and admin endpoints."""

from tests.route_paths import collect_route_paths


class TestHealthEndpoints:
    """Test health check endpoints."""

    def test_admin_health_endpoint_exists(self):
        """Admin health endpoint should be defined."""
        # This tests that the route is registered
        from main import app

        routes = collect_route_paths(app)
        assert "/admin/health" in routes

    def test_worker_queue_health_endpoint_exists(self):
        """Worker queue health endpoint should be defined."""
        from main import app

        routes = collect_route_paths(app)
        assert "/worker/queue-health" in routes

    def test_admin_users_endpoint_exists(self):
        """Admin users endpoint should be defined."""
        from main import app

        routes = collect_route_paths(app)
        assert "/admin/users" in routes
