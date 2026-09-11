"""Tests for app.schemas.models module."""


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

    def test_incident_model_keeps_legacy_description_and_alert_type(self):
        """The shared incident schema must preserve fields accepted by main.py."""
        from app.schemas.models import Incident

        incident = Incident(
            short_description="CPU spike",
            description="CPU is above the agreed threshold",
            alert_type_id=4,
        )
        assert incident.description == "CPU is above the agreed threshold"
        assert incident.alert_type_id == 4

    def test_incident_model_rejects_non_string_legacy_ids(self):
        """Incident IDs retain the legacy string-only validation contract."""
        import pytest
        from pydantic import ValidationError

        from app.schemas.models import Incident

        with pytest.raises(ValidationError):
            Incident(short_description="CPU spike", id=123)

    def test_cmdb_update_model_preserves_optional_metadata(self):
        """CMDB updates must retain every optional legacy metadata field."""
        from app.schemas.models import CMDBItemUpdate

        update = CMDBItemUpdate(
            sys_id="snow-123",
            source="servicenow",
            raw_data={"owner": "platform"},
        )
        assert update.sys_id == "snow-123"
        assert update.source == "servicenow"
        assert update.raw_data == {"owner": "platform"}

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
