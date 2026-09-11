"""Helpers for asserting FastAPI route registrations in tests."""


def collect_route_paths(app):
    """Collect paths from direct routes and included routers."""
    paths = []
    for route in app.routes:
        if hasattr(route, "path"):
            paths.append(route.path)
        elif hasattr(route, "routes"):
            for subroute in route.routes:
                if hasattr(subroute, "path"):
                    paths.append(subroute.path)
    return paths
