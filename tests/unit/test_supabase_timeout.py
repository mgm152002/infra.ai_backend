"""Tests for app.core.supabase_timeout module."""

import pytest
from unittest.mock import MagicMock, patch
import time

from app.core.supabase_timeout import run_supabase_with_timeout, SupabaseTimeoutError


class TestSupabaseTimeout:
    """Test Supabase query timeout wrapper."""

    def test_returns_result_within_timeout(self):
        """Should return result when query completes within timeout."""
        mock_result = MagicMock()
        mock_result.data = [{"id": 1}]

        def fast_query():
            return mock_result

        result = run_supabase_with_timeout(fast_query, timeout_s=5, operation_name="test")
        assert result.data == [{"id": 1}]

    def test_raises_timeout_error(self):
        """Should raise SupabaseTimeoutError when query exceeds timeout."""

        def slow_query():
            time.sleep(10)
            return MagicMock()

        with pytest.raises(SupabaseTimeoutError):
            run_supabase_with_timeout(slow_query, timeout_s=0.1, operation_name="slow_test")

    def test_propagates_query_exception(self):
        """Should propagate exceptions from the query function."""

        def failing_query():
            raise ValueError("Database connection failed")

        with pytest.raises(ValueError, match="Database connection failed"):
            run_supabase_with_timeout(failing_query, timeout_s=5, operation_name="fail_test")

    def test_operation_name_in_error(self):
        """Operation name should appear in timeout error message."""

        def slow_query():
            time.sleep(10)
            return MagicMock()

        with pytest.raises(SupabaseTimeoutError) as exc_info:
            run_supabase_with_timeout(slow_query, timeout_s=0.1, operation_name="my_operation")

        assert "my_operation" in str(exc_info.value)
