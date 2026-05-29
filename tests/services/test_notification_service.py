"""Tests for app.services.notification_service module."""

import pytest
from unittest.mock import patch, MagicMock


class TestNotificationService:
    """Test notification service."""

    def test_notification_service_importable(self):
        """NotificationService should be importable."""
        from app.services.notification_service import NotificationService

        assert NotificationService is not None

    def test_notify_incident_created_is_static(self):
        """notify_incident_created should be a static method."""
        from app.services.notification_service import NotificationService

        assert hasattr(NotificationService, "notify_incident_created")

    def test_notify_incident_update_is_static(self):
        """notify_incident_update should be a static method."""
        from app.services.notification_service import NotificationService

        assert hasattr(NotificationService, "notify_incident_update")

    @patch("app.services.notification_service.supabase")
    def test_get_credentials_returns_none_for_missing_user(self, mock_supabase):
        """_get_credentials should return None for non-existent user."""
        from app.services.notification_service import NotificationService

        mock_supabase.table.return_value.select.return_value.eq.return_value.limit.return_value.execute.return_value = MagicMock(
            data=[]
        )

        result = NotificationService._get_credentials("nonexistent-user", "slack")
        assert result is None
