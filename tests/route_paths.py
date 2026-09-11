"""Helpers for asserting FastAPI route registrations in tests."""

try:
    from fastapi.routing import iter_route_contexts
except ImportError:
    iter_route_contexts = None


def _context_path(context):
    path = getattr(context, "path", None)
    if path is not None:
        return path
    return getattr(getattr(context, "starlette_route", None), "path", None)


def _route_paths(route):
    if hasattr(route, "path"):
        return [route.path]

    if iter_route_contexts is not None:
        context_paths = [
            path
            for context in iter_route_contexts([route])
            if (path := _context_path(context)) is not None
        ]
        if context_paths:
            return context_paths

    if hasattr(route, "effective_route_contexts"):
        return [
            path
            for context in route.effective_route_contexts()
            if (path := _context_path(context)) is not None
        ]

    child_routes = getattr(route, "routes", None)
    if child_routes is None:
        child_routes = getattr(getattr(route, "original_router", None), "routes", [])
    return [subroute.path for subroute in child_routes if hasattr(subroute, "path")]


def collect_route_paths(app):
    """Collect paths from direct routes and included routers."""
    return [path for route in app.routes for path in _route_paths(route)]
