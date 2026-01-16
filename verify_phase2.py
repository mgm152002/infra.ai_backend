import sys
import os
import unittest
from unittest.mock import MagicMock, patch

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Mock langchain dependencies BEFORE importing app modules
sys.modules["langchain_core"] = MagicMock()
sys.modules["langchain_core.prompts"] = MagicMock()
sys.modules["langchain_core.output_parsers"] = MagicMock()
sys.modules["langchain_core.runnables"] = MagicMock()
sys.modules["app.api.routers.incidents"] = MagicMock() # Mock incidents router to avoid get_llm import issues

class TestPhase2Integrations(unittest.TestCase):
    
    def test_servicenow_module(self):
        """Verify ServiceNow credentials retrieval logic (mocked)."""
        # We need to act carefully because app.integrations.servicenow imports app.core.config
        
        with patch.dict(os.environ, {"INFISICAL_CLIENT_ID": "test", "INFISICAL_CLIENT_SECRET": "test"}):
             # Re-import to ensure mocks apply if needed or just import
             from app.integrations.servicenow import servicenow_client
             
             with patch('requests.post') as mock_post:
                # Mock Infisical login
                mock_post.return_value.status_code = 200
                mock_post.return_value.json.return_value = {'accessToken': 'fake-token'}
                
                with patch('requests.get') as mock_get:
                    # Mock secret retrieval
                    mock_get.return_value.status_code = 200
                    mock_get.return_value.json.return_value = {'secret': {'secretValue': 'secret-value'}}
                    
                    creds = servicenow_client._get_credentials_from_infisical("test@example.com")
                    self.assertEqual(creds['snow_key'], 'secret-value')
                    print("PASS: ServiceNow credential logic")

    def test_observability_factory(self):
        """Verify Observability Factory returns correct providers."""
        from app.core.observability import ObservabilityFactory, PrometheusProvider, DatadogProvider
        
        # Test Prometheus
        prom = ObservabilityFactory.get_provider("prometheus")
        self.assertIsInstance(prom, PrometheusProvider)
        
        # Test Datadog
        dd = ObservabilityFactory.get_provider("datadog")
        self.assertIsInstance(dd, DatadogProvider)
        print("PASS: Observability Factory")

    def test_chatops_service(self):
        """Verify ChatOps message sending (mocked)."""
        from app.integrations.chatops import chatops, ChannelType
        
        with patch('requests.post') as mock_post:
            chatops.slack_webhook_url = "http://fake-webhook"
            mock_post.return_value.status_code = 200
            
            result = chatops.send_message("Test message", "#general", ChannelType.SLACK)
            self.assertTrue(result)
            mock_post.assert_called_once()
            print("PASS: ChatOps Slack message")

if __name__ == "__main__":
    unittest.main()
