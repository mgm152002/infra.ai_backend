"""Tests for chat endpoints."""
import pytest
from unittest.mock import patch, MagicMock


class TestChatEndpoints:
    """Test chat session and message endpoints."""

    def test_chat_endpoint_exists(self):
        """/chat endpoint should be registered."""
        from main import app
        routes = [r.path for r in app.routes]
        assert "/chat" in routes

    def test_chat_stream_endpoint_exists(self):
        """/chat/stream endpoint should be registered."""
        from main import app
        routes = [r.path for r in app.routes]
        assert "/chat/stream" in routes

    def test_chat_async_endpoint_exists(self):
        """/chat/async endpoint should be registered."""
        from main import app
        routes = [r.path for r in app.routes]
        assert "/chat/async" in routes

    def test_chat_sessions_endpoint_exists(self):
        """/chat/sessions endpoint should be registered."""
        from main import app
        routes = [r.path for r in app.routes]
        assert "/chat/sessions" in routes

    def test_chat_history_endpoint_exists(self):
        """/chat/history endpoint should be registered."""
        from main import app
        routes = [r.path for r in app.routes]
        assert "/chat/history" in routes
