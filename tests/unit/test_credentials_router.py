def test_credentials_router_exposes_legacy_credential_routes():
    from app.api.routers.credentials import router

    paths = {route.path for route in router.routes}

    assert {
        "/uploadSSH",
        "/getSnowKey/{mail}",
        "/getSSHKeys/{mail}",
        "/getAwsKeys/{mail}",
        "/addSNOWCredentials",
        "/addAwsCredentials",
        "/updateSSH",
        "/updateServiceNow",
        "/prometheus/config",
        "/addSlackCredentials",
        "/getSlackCredentials/{mail}",
        "/addEmailCredentials",
        "/getEmailCredentials/{mail}",
    } <= paths
