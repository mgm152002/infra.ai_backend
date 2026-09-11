"""Tests for incident endpoints."""

from tests.route_paths import collect_route_paths


class TestIncidentEndpoints:
    """Test incident CRUD and analysis endpoints."""

    def test_incident_add_endpoint_exists(self):
        """Legacy /incidentAdd endpoint should be registered."""
        from main import app

        routes = collect_route_paths(app)
        assert "/incidentAdd" in routes

    def test_incidents_add_v3_endpoint_exists(self):
        """V3 /incidents/add endpoint should be registered."""
        from main import app

        routes = collect_route_paths(app)
        assert "/incidents/add" in routes

    def test_all_incidents_endpoint_exists(self):
        """/allIncidents endpoint should be registered."""
        from main import app

        routes = collect_route_paths(app)
        assert "/allIncidents" in routes

    def test_incidents_all_v3_endpoint_exists(self):
        """V3 /incidents/all endpoint should be registered."""
        from main import app

        routes = collect_route_paths(app)
        assert "/incidents/all" in routes

    def test_incident_stream_endpoint_exists(self):
        """Incident streaming endpoint should be registered."""
        from main import app

        routes = collect_route_paths(app)
        assert "/incident/stream" in routes

    def test_get_incidents_details_endpoint_exists(self):
        """Get incidents details endpoint should be registered."""
        from main import app

        routes = collect_route_paths(app)
        assert any("getIncidentsDetails" in r for r in routes)

    def test_incidents_analyze_endpoint_exists(self):
        """Incidents analyze endpoint should be registered."""
        from main import app

        routes = collect_route_paths(app)
        assert any("incidents" in r and "analyze" in r for r in routes)
