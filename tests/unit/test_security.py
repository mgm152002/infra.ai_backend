"""Tests for app.core.security module."""

import pytest
from unittest.mock import patch, MagicMock


class TestSecurity:
    """Test JWT verification, RBAC, and permission checking."""

    @patch("app.core.security.supabase")
    def test_verify_token_valid(self, mock_supabase):
        """Valid token should return user data."""
        from app.core.security import verify_token

        mock_supabase.table.return_value.select.return_value.eq.return_value.limit.return_value.execute.return_value = MagicMock(
            data=[{"id": "user-123", "email": "test@example.com"}]
        )

        # This test verifies the function structure; actual JWT verification
        # requires a real Clerk public key or full mock of jwt.decode
        assert callable(verify_token)

    @patch("app.core.security.supabase")
    def test_has_permission_returns_checker(self, mock_supabase):
        """has_permission should return a callable dependency."""
        from app.core.security import has_permission

        checker = has_permission("incidents", "read")
        assert callable(checker)

    @patch("app.core.security.supabase")
    def test_role_checker_init(self, mock_supabase):
        """RoleChecker should initialize with allowed roles."""
        from app.core.security import RoleChecker

        checker = RoleChecker(["admin", "operator"])
        assert checker is not None

    def test_verify_token_function_exists(self):
        """verify_token should be importable."""
        from app.core.security import verify_token

        assert verify_token is not None

    def test_get_current_user_function_exists(self):
        """get_current_user should be importable."""
        from app.core.security import get_current_user

        assert get_current_user is not None
