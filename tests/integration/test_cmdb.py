"""Tests for CMDB endpoints."""

from tests.route_paths import collect_route_paths


class TestCMDBEndpoints:
    """Test CMDB CRUD endpoints."""

    def test_cmdb_endpoint_exists(self):
        """CMDB endpoint should be registered."""
        from main import app

        routes = collect_route_paths(app)
        assert "/cmdb" in routes

    def test_cmdb_by_service_endpoint_exists(self):
        """CMDB by-service endpoint should be registered."""
        from main import app

        routes = collect_route_paths(app)
        assert "/cmdb/by-service" in routes

    def test_cmdb_search_endpoint_exists(self):
        """CMDB search endpoint should be registered."""
        from main import app

        routes = collect_route_paths(app)
        assert any("cmdb/search" in r for r in routes)

    def test_services_endpoint_exists(self):
        """Services endpoint should be registered."""
        from main import app

        routes = collect_route_paths(app)
        assert "/services" in routes

    def test_services_hosts_endpoint_exists(self):
        """Services hosts endpoint should be registered."""
        from main import app

        routes = collect_route_paths(app)
        assert any("services" in r and "hosts" in r for r in routes)

    def test_upload_cmdb_endpoint_exists(self):
        """Upload CMDB endpoint should be registered."""
        from main import app

        routes = collect_route_paths(app)
        assert "/uploadCMDB" in routes

    def test_cmdb_router_preserves_the_cmdb_and_service_contract(self):
        """The extracted router must expose every moved CMDB/service route."""
        from app.api.routers.cmdb import router

        routes = {(route.path, method) for route in router.routes for method in route.methods}
        assert ("/cmdb", "GET") in routes
        assert ("/cmdb", "POST") in routes
        assert ("/cmdb/{tag_id}", "PUT") in routes
        assert ("/cmdb/{tag_id}", "DELETE") in routes
        assert ("/cmdb/by-service", "GET") in routes
        assert ("/cmdb/search/{query}", "GET") in routes
        assert ("/services", "GET") in routes
        assert ("/services", "POST") in routes
        assert ("/services/{service_id}", "GET") in routes
        assert ("/services/{service_id}", "PUT") in routes
        assert ("/services/{service_id}", "DELETE") in routes
        assert ("/services/{service_id}/hosts", "GET") in routes
