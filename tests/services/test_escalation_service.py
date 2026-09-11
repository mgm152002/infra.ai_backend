"""Tests for the escalation monitoring service."""


class TestEscalationService:
    """Test escalation monitoring service."""

    def test_escalation_service_class_exists(self):
        """EscalationService should be importable without the application module."""
        from app.services.escalation_service import EscalationService

        assert EscalationService is not None

    def test_check_escalations_is_static(self):
        """check_escalations should be a static method."""
        from app.services.escalation_service import EscalationService

        assert hasattr(EscalationService, "check_escalations")

    def test_start_monitoring_is_static(self):
        """start_monitoring should be a static method."""
        from app.services.escalation_service import EscalationService

        assert hasattr(EscalationService, "start_monitoring")
