"""Shared pytest fixtures for infra-ai-backend tests."""

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# --- CRITICAL: Set env vars BEFORE any imports ---

os.environ["SUPABASE_URL"] = "https://test.supabase.co"
os.environ["SUPABASE_KEY"] = "test-key"
os.environ["AWS_REGION"] = "us-east-1"
os.environ["SQS_QUEUE_NAME"] = "test-queue"
os.environ["ENCRYPTION_KEY"] = "dGVzdC1rZXktZm9yLXRlc3Rpbmctb25seS0xMjM0NTY3OA=="

# --- Mock Supabase classes ---


class MockSupabaseResponse:
    """Mimics Supabase query response."""

    def __init__(self, data=None, count=None):
        self.data = data or []
        self.count = count


class MockSupabaseQuery:
    """Chainable mock for Supabase query builder."""

    def __init__(self, return_data=None):
        self._return_data = return_data or []

    def select(self, *args, **kwargs):
        return self

    def insert(self, *args, **kwargs):
        return self

    def update(self, *args, **kwargs):
        return self

    def upsert(self, *args, **kwargs):
        return self

    def delete(self, *args, **kwargs):
        return self

    def eq(self, *args, **kwargs):
        return self

    def neq(self, *args, **kwargs):
        return self

    def in_(self, *args, **kwargs):
        return self

    def or_(self, *args, **kwargs):
        return self

    def order(self, *args, **kwargs):
        return self

    def limit(self, *args, **kwargs):
        return self

    def range(self, *args, **kwargs):
        return self

    def execute(self):
        return MockSupabaseResponse(data=self._return_data)

    def single(self):
        return self


class MockSupabaseClient:
    """Full mock Supabase client."""

    def __init__(self, return_data=None):
        self._return_data = return_data or []
        self.auth = MagicMock()

    def table(self, table_name):
        return MockSupabaseQuery(self._return_data)

    def from_(self, table_name):
        return MockSupabaseQuery(self._return_data)


def _create_mock_client(*args, **kwargs):
    """Factory function for mock Supabase client."""
    return MockSupabaseClient()


# --- Apply mocks BEFORE importing anything from app ---

# Patch 1: supabase.create_client function
_supabase_create_patch = patch("supabase.create_client", side_effect=_create_mock_client)
_supabase_create_patch.start()

# Patch 2: supabase.Client class directly
_supabase_client_patch = patch("supabase.Client", MockSupabaseClient)
_supabase_client_patch.start()

# Patch 3: The module where database.py imports from
_db_module_patch = patch(
    "app.core.database.create_client", side_effect=_create_mock_client
)
_db_module_patch.start()

# Now safe to import pytest
import pytest  # noqa: E402


def pytest_configure(config):
    """Called before test collection - ensure mocks are in place."""
    # Re-apply patches to ensure they're active
    if not _supabase_create_patch.is_local:
        _supabase_create_patch.start()
    if not _supabase_client_patch.is_local:
        _supabase_client_patch.start()
    if not _db_module_patch.is_local:
        _db_module_patch.start()


def pytest_unconfigure(config):
    """Called after all tests complete."""
    _supabase_create_patch.stop()
    _supabase_client_patch.stop()
    _db_module_patch.stop()


@pytest.fixture(scope="session", autouse=True)
def setup_mocks():
    """Ensure mocks stay active for entire test session."""
    yield
    # Mocks stopped in pytest_unconfigure


@pytest.fixture
def mock_supabase():
    """Provide a mock Supabase client."""
    return MockSupabaseClient()


@pytest.fixture
def mock_supabase_with_data():
    """Factory fixture to create a mock Supabase client with specific return data."""

    def _factory(data):
        return MockSupabaseClient(return_data=data)

    return _factory


# --- Auth fixtures ---


@pytest.fixture
def mock_verify_token():
    """Mock auth dependency that returns a valid user payload."""
    return {
        "user_id": "test-user-123",
        "email": "test@example.com",
        "sub": "clerk_user_123",
    }


@pytest.fixture
def authenticated_headers():
    """Pre-built auth headers for test requests."""
    return {"Authorization": "Bearer test-token"}


# --- LLM fixtures ---


@pytest.fixture
def mock_llm():
    """Mock LLM that returns configurable responses."""
    mock = MagicMock()
    mock.invoke.return_value = MagicMock(
        content='{"potential_cause": "test cause", "potential_solution": "test solution"}'
    )
    return mock


@pytest.fixture
def mock_call_llm():
    """Patch the call_llm function."""
    with patch("app.core.llm.call_llm") as mock:
        mock.return_value = "test LLM response"
        yield mock


# --- Settings fixture ---


@pytest.fixture
def mock_settings():
    """Mock settings object."""
    settings = MagicMock()
    settings.SQS_QUEUE_NAME = "test-queue"
    settings.AWS_REGION = "us-east-1"
    settings.SUPABASE_URL = "https://test.supabase.co"
    settings.SUPABASE_KEY = "test-key"
    return settings
