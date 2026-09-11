"""Tests for route discovery across included routers."""


def test_collect_route_paths_includes_direct_and_nested_routes():
    """Included routers contribute their child paths to endpoint assertions."""
    from types import SimpleNamespace

    from tests.route_paths import collect_route_paths

    app = SimpleNamespace(
        routes=[
            SimpleNamespace(path="/health"),
            SimpleNamespace(
                routes=[
                    SimpleNamespace(path="/cmdb"),
                    SimpleNamespace(path="/services"),
                ]
            ),
        ]
    )

    assert collect_route_paths(app) == ["/health", "/cmdb", "/services"]


def test_collect_route_paths_follows_lazy_included_router_children():
    """Lazy FastAPI wrappers expose child routes through original_router."""
    from types import SimpleNamespace

    from tests.route_paths import collect_route_paths

    app = SimpleNamespace(
        routes=[
            SimpleNamespace(original_router=SimpleNamespace(routes=[SimpleNamespace(path="/cmdb")]))
        ]
    )

    assert collect_route_paths(app) == ["/cmdb"]


def test_collect_route_paths_prefers_effective_route_contexts(monkeypatch):
    """Effective contexts retain prefixes from included routers."""
    from types import SimpleNamespace

    import tests.route_paths as route_paths

    app = SimpleNamespace(routes=[SimpleNamespace()])
    monkeypatch.setattr(
        route_paths,
        "iter_route_contexts",
        lambda routes: [SimpleNamespace(path="/api/v1/workflow/alert-types")],
        raising=False,
    )

    assert route_paths.collect_route_paths(app) == ["/api/v1/workflow/alert-types"]
