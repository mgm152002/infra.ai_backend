"""Helpers for asserting the application's documented HTTP contract."""


def collect_route_contract(app):
    """Return every documented HTTP method and path."""
    return {
        (path, method.upper())
        for path, operations in app.openapi()["paths"].items()
        for method in operations
        if method.lower() in {"get", "post", "put", "patch", "delete", "options", "head"}
    }
