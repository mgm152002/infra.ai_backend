"""
SSE (Server-Sent Events) manager for real-time incident updates.
This module provides a simple event emitter that can stream events to connected clients.
"""
import json
import threading
from typing import Dict, List, Callable, Any
from collections import defaultdict
from datetime import datetime


class SSEManager:
    """
    Manages SSE connections and broadcasts events to all connected clients.
    """
    def __init__(self):
        self._clients: Dict[str, List[Callable]] = defaultdict(list)
        self._incident_events: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self._max_events_per_incident = 250
        self._lock = threading.Lock()
    
    def connect(self, client_id: str, callback: Callable):
        """Register a callback for a specific client."""
        with self._lock:
            self._clients[client_id].append(callback)
    
    def disconnect(self, client_id: str, callback: Callable = None):
        """Unregister a client or specific callback."""
        with self._lock:
            if callback:
                if callback in self._clients[client_id]:
                    self._clients[client_id].remove(callback)
            else:
                self._clients.pop(client_id, None)
    
    def broadcast(self, event_type: str, data: Any, client_id: str = None):
        """Broadcast an event to all connected clients or a specific client."""
        event = {
            "type": event_type,
            "data": data,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        with self._lock:
            if client_id:
                callbacks = self._clients.get(client_id, []).copy()
            else:
                # Broadcast to all clients
                callbacks = []
                for client_callbacks in self._clients.values():
                    callbacks.extend(client_callbacks)
        
        for callback in callbacks:
            try:
                callback(event)
            except Exception:
                pass  # Ignore callback errors
    
    def emit_incident_event(self, incident_id: str, event_type: str, data: Any):
        """Emit an incident-specific event."""
        event = {
            "type": event_type,
            "data": {
                "incident_id": incident_id,
                **(data or {}),
            },
            "timestamp": datetime.utcnow().isoformat(),
        }

        with self._lock:
            history = self._incident_events[incident_id]
            history.append(event)
            if len(history) > self._max_events_per_incident:
                del history[: len(history) - self._max_events_per_incident]

            callbacks: List[Callable] = []
            for client_callbacks in self._clients.values():
                callbacks.extend(client_callbacks)

        for callback in callbacks:
            try:
                callback(event)
            except Exception:
                pass

    def get_recent_incident_events(self, incident_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Return most recent in-memory events for a single incident."""
        if not incident_id:
            return []
        safe_limit = max(1, min(int(limit or 100), self._max_events_per_incident))
        with self._lock:
            history = list(self._incident_events.get(incident_id, []))
        if not history:
            return []
        return history[-safe_limit:]


# Global SSE manager instance
sse_manager = SSEManager()


def format_sse_event(event_type: str, data: Any) -> str:
    """Format data as an SSE event."""
    return f"event: {event_type}\ndata: {json.dumps(data)}\n\n"


def create_sse_response(events: List[tuple]) -> str:
    """Create SSE response string from list of (event_type, data) tuples."""
    response = ""
    for event_type, data in events:
        response += format_sse_event(event_type, data)
    return response
