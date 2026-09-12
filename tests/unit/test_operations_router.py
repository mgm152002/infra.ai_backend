def test_operations_router_exposes_legacy_operational_routes():
    from app.api.routers.operations import router

    paths = {route.path for route in router.routes}

    assert {
        "/queueAdd",
        "/queueRemove",
        "/testecodeexec/{hostname}/{username}",
        "/testAws",
        "/websearch",
        "/plan",
        "/storeResult",
        "/getResults/{inc_number}",
        "/getRCA/{inc_number}",
        "/generateRCA/{inc_number}",
        "/jobs/active",
        "/jobs/{job_id}",
        "/uploadCMDB",
        "/admin/users",
        "/admin/health",
        "/worker/queue-health",
    } <= paths
