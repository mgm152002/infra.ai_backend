"""Tests for workflow and alert management endpoints."""
import pytest
from unittest.mock import patch, MagicMock


class TestWorkflowEndpoints:
    """Test alert types, escalation rules, and change management endpoints."""

    def test_alert_types_endpoint_exists(self):
        """/alert-types endpoint should be registered."""
        from main import app
        routes = [r.path for r in app.routes]
        assert "/alert-types" in routes

    def test_escalation_rules_endpoint_exists(self):
        """/escalation-rules endpoint should be registered."""
        from main import app
        routes = [r.path for r in app.routes]
        assert "/escalation-rules" in routes

    def test_alert_type_escalations_endpoint_exists(self):
        """/alert-type-escalations endpoint should be registered."""
        from main import app
        routes = [r.path for r in app.routes]
        assert "/alert-type-escalations" in routes

    def test_pending_actions_endpoint_exists(self):
        """/pending-actions endpoint should be registered."""
        from main import app
        routes = [r.path for r in app.routes]
        assert "/pending-actions" in routes

    def test_workflow_router_prefix(self):
        """Workflow router should be mounted at /api/v1/workflow."""
        from main import app
        routes = [r.path for r in app.routes]
        assert any("/api/v1/workflow" in r for r in routes)
