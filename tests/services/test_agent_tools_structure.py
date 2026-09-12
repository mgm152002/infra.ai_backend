"""Tests for the agent-tool module boundary."""

from pathlib import Path


def test_agent_tools_exports_chat_registry():
    from app.services.agent_tools import (
        CHAT_SYSTEM_PROMPT,
        TOOLS_REQUIRING_MAIL,
        llm_with_tools,
        tool_mapping,
    )

    assert CHAT_SYSTEM_PROMPT
    assert isinstance(TOOLS_REQUIRING_MAIL, set)
    assert llm_with_tools is not None
    assert tool_mapping


def test_incident_service_does_not_import_main():
    source = Path("app/services/incident_service.py").read_text()
    assert "from main import" not in source


def test_infrastructure_automation_owns_its_implementation():
    infrastructure_source = Path("app/services/infrastructure_automation.py").read_text()
    agent_tools_source = Path("app/services/agent_tools.py").read_text()

    assert "def infra_automation_ai" in infrastructure_source
    assert "def infra_automation_ai" not in agent_tools_source
