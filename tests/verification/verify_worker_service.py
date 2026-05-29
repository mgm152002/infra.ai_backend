import sys
from unittest.mock import MagicMock

# Mock all heavy dependencies
sys.modules["paramiko"] = MagicMock()
sys.modules["boto3"] = MagicMock()
sys.modules["supabase"] = MagicMock()
sys.modules["pinecone"] = MagicMock()
sys.modules["openai"] = MagicMock()
sys.modules["langchain_openai"] = MagicMock()
sys.modules["langchain_core"] = MagicMock()
sys.modules["langchain_core.messages"] = MagicMock()
sys.modules["google"] = MagicMock()
sys.modules["google.generativeai"] = MagicMock()
sys.modules["integrations"] = MagicMock()
sys.modules["integrations.github"] = MagicMock()
sys.modules["integrations.jira"] = MagicMock()
sys.modules["integrations.confluence"] = MagicMock()
sys.modules["integrations.pagerduty"] = MagicMock()

import os
# Set dummy env vars
os.environ["OPENROUTER_API_KEY"] = "dummy"
os.environ["SUPABASE_URL"] = "http://dummy"
os.environ["SUPABASE_KEY"] = "dummy"

from unittest.mock import patch
# Patch logger
with patch("app.core.logger.logger"):
    from app.services.incident_service import process_incident


def test_process_incident_flow():
    print("Testing process_incident flow...")
    
    # Mock data
    aws_data = {"instance_id": "i-12345"}
    mail_data = {"inc_number": "INC-001", "subject": "Test Incident", "message": "Something is broken"}
    meta_data = {"tag_id": "tag-123", "user_id": "user-1"}
    
    # Mocks
    mock_supabase = MagicMock()
    mock_llm = MagicMock()
    
    # Setup Supabase Mocks
    # 1. Update state "Processing" -> ok
    # 2. CMDB lookup -> returns record
    mock_supabase.table.return_value.select.return_value.eq.return_value.eq.return_value.execute.return_value.data = [
        {"id": "cmdb-1", "user_id": "user-1", "os": "ubuntu", "ip": "1.2.3.4", "tag_id": "tag-123"}
    ]
    # 3. User lookup -> returns email
    mock_supabase.table.return_value.select.return_value.eq.return_value.execute.return_value.data = [
        {"email": "test@example.com"}
    ]
    
    # Setup LLM Mock
    # collect_diagnostics -> returns plan
    # analyze_diagnostics -> returns analysis
    # execute_resolution -> returns resolution
    
    # We need to be more specific with side effects if we want to trace distinct calls, 
    # but for a basic smoke test, one return value is often enough if the parsers are robust.
    # However, our parsers expect JSON.
    
    json_responses = [
        # collect_diagnostics
        '{"todos": [{"step": "check uptime", "command": "uptime", "expected_output": "up"}]}',
        # analyze_diagnostics
        '{"root_cause": "cpu spike", "resolution_steps": ["restart service"], "verification": "check status"}',
        # execute_resolution (command generation)
        'sudo systemctl restart service'
    ]
    
    mock_llm_calls = iter(json_responses)
    def mock_call_llm(*args, **kwargs):
        try:
            return next(mock_llm_calls)
        except StopIteration:
            return "{}"

    # Patch dependencies
    with patch("app.services.incident_service.supabase", mock_supabase), \
         patch("app.services.incident_service.call_llm", side_effect=mock_call_llm), \
         patch("app.services.incident_service.fetch_ssh_key_content", return_value="fake-key-content"), \
         patch("app.services.incident_service.run_shell_command", return_value={"success": True, "output": "ok"}), \
         patch("app.services.incident_service.get_incident_runbook_context", return_value={}), \
         patch("app.services.incident_service.fetch_external_integrations_context", return_value=""), \
         patch("app.services.incident_service.fetch_prometheus_metrics", return_value=""):

        result = process_incident(aws_data, mail_data, meta_data)
        
        print(f"Result Status: {result.get('status')}")
        assert result.get('status') == "Resolved"
        print("PASS: process_incident returned Resolved")

if __name__ == "__main__":
    try:
        test_process_incident_flow()
        print("\nWorker Service tests passed!")
    except Exception as e:
        print(f"\nTests Failed: {e}")
        import traceback
        traceback.print_exc()
