"""Tests for app.core.sse_manager module."""
import pytest
from unittest.mock import MagicMock

from app.core.sse_manager import SSEManager


class TestSSEManager:
    """Test SSE pub/sub manager."""

    @pytest.fixture
    def manager(self):
        return SSEManager()

    def test_connect_registers_callback(self, manager):
        """Connecting should register a callback for a client."""
        callback = MagicMock()
        manager.connect("client-1", callback)
        assert callback in manager._clients["client-1"]

    def test_disconnect_removes_client(self, manager):
        """Disconnecting without callback should remove the entire client."""
        callback = MagicMock()
        manager.connect("client-1", callback)
        manager.disconnect("client-1")
        assert "client-1" not in manager._clients

    def test_disconnect_removes_specific_callback(self, manager):
        """Disconnecting with callback should remove only that callback."""
        callback1 = MagicMock()
        callback2 = MagicMock()
        manager.connect("client-1", callback1)
        manager.connect("client-1", callback2)
        manager.disconnect("client-1", callback1)
        assert callback1 not in manager._clients.get("client-1", [])
        assert callback2 in manager._clients.get("client-1", [])

    def test_broadcast_sends_to_connected_clients(self, manager):
        """Broadcasting should invoke callbacks for connected clients."""
        callback = MagicMock()
        manager.connect("client-1", callback)
        manager.broadcast("status", {"message": "processing"}, client_id="client-1")
        callback.assert_called_once()

    def test_emit_incident_event_stores_in_history(self, manager):
        """emit_incident_event should store events in incident history."""
        callback = MagicMock()
        manager.connect("client-1", callback)
        manager.emit_incident_event("INC-001", "status", {"message": "processing"})
        events = manager.get_recent_incident_events("INC-001")
        assert len(events) == 1

    def test_get_recent_incident_events_returns_stored_events(self, manager):
        """get_recent_incident_events should return previously stored events."""
        callback = MagicMock()
        manager.connect("client-1", callback)
        manager.emit_incident_event("INC-001", "event1", {"data": "a"})
        manager.emit_incident_event("INC-001", "event2", {"data": "b"})

        events = manager.get_recent_incident_events("INC-001")
        assert len(events) == 2

    def test_empty_history_for_unknown_incident(self, manager):
        """get_recent_incident_events should return empty list for unknown incident."""
        events = manager.get_recent_incident_events("nonexistent")
        assert events == []

    def test_callback_failure_handling(self, manager):
        """Manager should handle callback failures gracefully."""
        failing_callback = MagicMock(side_effect=Exception("Connection lost"))
        manager.connect("client-1", failing_callback)
        # Should not raise
        manager.broadcast("test", {"data": "value"}, client_id="client-1")

    def test_multiple_clients(self, manager):
        """Multiple clients should be able to connect."""
        callback1 = MagicMock()
        callback2 = MagicMock()
        manager.connect("client-1", callback1)
        manager.connect("client-2", callback2)
        assert len(manager._clients) == 2

    def test_emit_incident_event_invokes_callbacks(self, manager):
        """emit_incident_event should invoke all connected callbacks."""
        callback = MagicMock()
        manager.connect("client-1", callback)
        manager.emit_incident_event("INC-001", "status", {"message": "done"})
        callback.assert_called_once()
