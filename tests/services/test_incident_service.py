"""Tests for app.services.incident_service module."""

import pytest
from unittest.mock import patch, MagicMock


class TestIncidentService:
    """Test incident processing service."""

    def test_incident_service_importable(self):
        """incident_service should be importable."""
        from app.services.incident_service import process_incident

        assert callable(process_incident)

    def test_process_incident_streaming_importable(self):
        """process_incident_streaming should be importable."""
        from app.services.incident_service import process_incident_streaming

        assert callable(process_incident_streaming)

    def test_emit_sse_incident_event_importable(self):
        """emit_sse_incident_event should be importable."""
        from app.services.incident_service import emit_sse_incident_event

        assert callable(emit_sse_incident_event)
