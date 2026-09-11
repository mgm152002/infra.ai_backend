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
