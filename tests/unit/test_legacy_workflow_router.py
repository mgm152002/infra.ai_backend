def test_legacy_workflow_router_exposes_unprefixed_routes():
    from app.api.routers.legacy_workflow import router

    paths = {route.path for route in router.routes}

    assert {
        "/alert-types",
        "/alert-types/{alert_id}",
        "/escalation-rules",
        "/escalation-rules/{rule_id}",
        "/alert-type-escalations",
        "/alert-type-escalations/{alert_type_id}",
        "/pending-actions",
        "/pending-actions/{action_id}/approve",
        "/pending-actions/{action_id}/reject",
    } <= paths
