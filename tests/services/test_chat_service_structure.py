from pathlib import Path


def test_chat_service_exports_worker_and_request_processor():
    from app.services.chat_service import chat_worker_loop, process_chat_request

    assert callable(chat_worker_loop)
    assert callable(process_chat_request)


def test_chat_router_does_not_import_main():
    source = Path("app/api/routers/chat.py").read_text()

    assert "from main import" not in source
