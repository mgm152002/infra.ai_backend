"""Tests for app.schemas.models module."""
import pytest
from datetime import datetime


class TestSchemas:
    """Test Pydantic schema models."""

    def test_incident_model_creation(self):
        """Incident model should accept valid data."""
        from app.schemas.models import Incident

        incident = Incident(
            short_description="Test incident",
            tag_id="server-001",
            state="Queued",
        )
        assert incident.short_description == "Test incident"
        assert incident.tag_id == "server-001"
        assert incident.state == "Queued"

    def test_incident_model_defaults(self):
        """Incident model should have sensible defaults."""
        from app.schemas.models import Incident

        incident = Incident(short_description="Test")
        assert incident.state is None
        assert incident.source is None
        assert incident.tag_id is None

    def test_alert_type_escalation_model(self):
        """AlertTypeEscalation model should accept valid data."""
        from app.schemas.models import AlertTypeEscalation

        escalation = AlertTypeEscalation(
            alert_type_id="cpu_high",
            alert_type_name="High CPU",
            escalation_level=1,
            notification_channels=["slack"],
            notification_destination="#alerts",
            escalation_timeout_minutes=15,
            auto_escalate=True,
        )
        assert escalation.alert_type_id == "cpu_high"
        assert escalation.escalation_level == 1
        assert escalation.auto_escalate is True

    def test_alert_type_escalation_update_model(self):
        """AlertTypeEscalationUpdate should accept partial updates."""
        from app.schemas.models import AlertTypeEscalationUpdate

        update = AlertTypeEscalationUpdate(
            escalation_level=2,
            auto_escalate=False,
        )
        assert update.escalation_level == 2
        assert update.auto_escalate is False

    def test_credentials_slack_config(self):
        """SlackConfig should accept valid data."""
        from app.schemas.credentials import SlackConfig

        config = SlackConfig(
            slack_bot_token="xoxb-test-token",
            slack_channel="#test-channel",
        )
        assert config.slack_bot_token == "xoxb-test-token"
        assert config.slack_channel == "#test-channel"

    def test_credentials_email_config(self):
        """EmailConfig should accept valid data."""
        from app.schemas.credentials import EmailConfig

        config = EmailConfig(
            smtp_server="smtp.gmail.com",
            smtp_port=587,
            sender_email="test@example.com",
            sender_password="password123",
        )
        assert config.smtp_server == "smtp.gmail.com"
        assert config.smtp_port == 587
