"""Tests for knowledge route ownership."""


def test_knowledge_router_owns_all_knowledge_paths():
    from app.api.routers.knowledge import router

    paths = {route.path for route in router.routes}
    assert paths == {
        "/addKnowledge",
        "/knowledge/architecture",
        "/knowledge/architecture/docs",
        "/getKnowledge",
        "/knowledge/docs",
        "/knowledge/{doc_id}",
    }
