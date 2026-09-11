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


def collect_route_paths(app):
    """Collect paths from direct routes and included routers."""
    if iter_route_contexts is not None:
        return [
            path
            for context in iter_route_contexts(app.routes)
            if (path := _context_path(context)) is not None
        ]

    paths = []
    for route in app.routes:
        if hasattr(route, "path"):
            paths.append(route.path)
        elif hasattr(route, "effective_route_contexts"):
            paths.extend(
                path
                for context in route.effective_route_contexts()
                if (path := _context_path(context)) is not None
            )
        elif hasattr(route, "routes"):
            for subroute in route.routes:
                if hasattr(subroute, "path"):
                    paths.append(subroute.path)
        elif hasattr(route, "original_router"):
            for subroute in route.original_router.routes:
                if hasattr(subroute, "path"):
                    paths.append(subroute.path)
    return paths
