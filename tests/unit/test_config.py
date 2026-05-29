"""Tests for app.core.config module."""

import pytest
from unittest.mock import patch


class TestConfig:
    """Test settings configuration."""

    def test_settings_is_importable(self):
        """Settings should be importable."""
        from app.core.config import settings

        assert settings is not None

    def test_settings_has_supabase_url(self):
        """Settings should have SUPABASE_URL attribute."""
        from app.core.config import settings

        assert hasattr(settings, "SUPABASE_URL")

    def test_settings_has_supabase_key(self):
        """Settings should have SUPABASE_KEY attribute."""
        from app.core.config import settings

        assert hasattr(settings, "SUPABASE_KEY")

    def test_settings_has_sqs_queue_name(self):
        """Settings should have SQS_QUEUE_NAME attribute."""
        from app.core.config import settings

        assert hasattr(settings, "SQS_QUEUE_NAME")

    def test_settings_has_aws_region(self):
        """Settings should have AWS_REGION attribute."""
        from app.core.config import settings

        assert hasattr(settings, "AWS_REGION")
