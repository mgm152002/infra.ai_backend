"""Root conftest.py - loaded BEFORE test collection begins."""

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# --- CRITICAL: Set env vars BEFORE any imports ---

os.environ["SUPABASE_URL"] = "https://test.supabase.co"
os.environ["SUPABASE_KEY"] = "test-key"
os.environ["AWS_REGION"] = "us-east-1"
os.environ["SQS_QUEUE_NAME"] = "test-queue"
os.environ["ENCRYPTION_KEY"] = "dGVzdC1rZXktZm9yLXRlc3Rpbmctb25seS0xMjM0NTY3OA=="

# --- CRITICAL: Mock missing dependencies BEFORE importing app ---

# Mock pinecone_plugins (not installed in CI)
_pinecone_mock = MagicMock()
sys.modules["pinecone_plugins"] = _pinecone_mock
sys.modules["pinecone_plugins.assistant"] = _pinecone_mock.assistant
sys.modules["pinecone_plugins.assistant.models"] = _pinecone_mock.assistant.models
sys.modules["pinecone_plugins.assistant.models.chat"] = _pinecone_mock.assistant.models.chat

# Mock langchain_openai (optional dependency)
_langchain_mock = MagicMock()
_langchain_mock.ChatOpenAI = MagicMock
sys.modules["langchain_openai"] = _langchain_mock
