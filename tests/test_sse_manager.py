from app.core.sse_manager import SSEManager, create_sse_response, format_sse_event


def test_broadcast_targets_a_single_client():
    manager = SSEManager()
    received_events = []

    manager.connect("client-a", received_events.append)
    manager.broadcast("incident.updated", {"id": "INC-1"}, client_id="client-a")

    assert len(received_events) == 1
    assert received_events[0]["type"] == "incident.updated"
    assert received_events[0]["data"] == {"id": "INC-1"}
    assert "timestamp" in received_events[0]


def test_disconnect_removes_only_the_selected_callback():
    manager = SSEManager()
    first_client_events = []
    second_client_events = []

    manager.connect("client-a", first_client_events.append)
    manager.connect("client-a", second_client_events.append)
    manager.disconnect("client-a", first_client_events.append)
    manager.broadcast("incident.updated", {"id": "INC-2"}, client_id="client-a")

    assert first_client_events == []
    assert len(second_client_events) == 1


def test_emit_incident_event_keeps_only_recent_history():
    manager = SSEManager()
    manager._max_events_per_incident = 2

    manager.emit_incident_event("INC-7", "queued", {"step": 1})
    manager.emit_incident_event("INC-7", "running", {"step": 2})
    manager.emit_incident_event("INC-7", "complete", {"step": 3})

    recent_events = manager.get_recent_incident_events("INC-7", limit=10)

    assert [event["type"] for event in recent_events] == ["running", "complete"]
    assert recent_events[-1]["data"]["incident_id"] == "INC-7"
    assert recent_events[-1]["data"]["step"] == 3


def test_callback_failures_do_not_stop_other_subscribers():
    manager = SSEManager()
    successful_events = []

    def broken_callback(_event):
        raise RuntimeError("subscriber failed")

    manager.connect("client-a", broken_callback)
    manager.connect("client-b", successful_events.append)

    manager.broadcast("incident.updated", {"id": "INC-5"})

    assert len(successful_events) == 1


def test_sse_helpers_build_valid_payloads():
    event = format_sse_event("message", {"status": "ok"})
    response = create_sse_response([("message", {"status": "ok"}), ("done", {"id": "INC-9"})])

    assert event == 'event: message\ndata: {"status": "ok"}\n\n'
    assert response.count("event:") == 2
    assert 'data: {"id": "INC-9"}' in response
