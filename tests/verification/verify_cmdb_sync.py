import sys
import os
import unittest
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient
import json
from datetime import datetime

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# --- MOCKS ---
# Mock external services
sys.modules["app.core.logger"] = MagicMock()
sys.modules["app.core.encryption"] = MagicMock()
sys.modules["langchain_openai"] = MagicMock() # Mock langchain_openai
sys.modules["langchain_core"] = MagicMock()
sys.modules["langchain_core.prompts"] = MagicMock()
sys.modules["langchain_core.output_parsers"] = MagicMock()
sys.modules["langchain_core.runnables"] = MagicMock()
sys.modules["langchain_core.runnables"] = MagicMock()
# sys.modules["app.api.routers.incidents"] = MagicMock()  <-- REMOVED 

# Mock Supabase
mock_supabase = MagicMock()
mock_database = MagicMock()
mock_database.supabase = mock_supabase
sys.modules["app.core.database"] = mock_database
sys.modules["app.api.routers.main"] = MagicMock()
sys.modules["app.api.routers.main"].supabase = mock_supabase

# Mock verify_token
mock_verify_token = MagicMock()
mock_verify_token.return_value = {"email": "test@example.com", "user_id": "user-123"}

# Mock security
security_mock = MagicMock()
security_mock.verify_token = mock_verify_token

def mock_has_perm_factory(*args, **kwargs):
    def dep(): return True
    return dep

security_mock.has_permission.side_effect = mock_has_perm_factory
sys.modules["app.core.security"] = security_mock

# Import Router and Task
from app.api.routers import integrations, incidents
from app.api.routers.integrations import background_sync_task

class TestCMDBSync(unittest.TestCase):
    def setUp(self):
        from fastapi import FastAPI
        self.app = FastAPI()
        self.app.include_router(integrations.router)
        self.app.include_router(incidents.router, prefix="/incidents")
        self.client = TestClient(self.app)
        
        # Override dependency
        self.app.dependency_overrides[mock_verify_token] = lambda: {"email": "test@example.com", "user_id": "user-123"}
        
        # Reset mocks
        mock_supabase.reset_mock()

    @patch("app.api.routers.integrations.servicenow_client.fetch_cmdb_assets")
    def test_background_sync_logic(self, mock_fetch):
        # 1. Setup Mock Assets (SNOW)
        mock_assets = [
            {
                "name": "server-01", 
                "sys_id": "sys-001", 
                "sys_class_name": "server", 
                "manufacturer": "Dell"
            },
            {
                "name": "server-02", 
                "sys_id": "sys-002", 
                "sys_class_name": "server"
            }
        ]
        mock_fetch.return_value = mock_assets
        
        # 2. Setup Mock Existing DB Items (to test collision logic)
        existing_items = [
            {"id": "uuid-1", "sys_id": "sys-001", "tag_id": "server-01"},
            {"id": "uuid-2", "sys_id": None, "tag_id": "server-02"}
        ]
        
        mock_execute = MagicMock()
        mock_execute.data = existing_items
        
        # We need to handle multiple table calls: "Jobs" and "CMDB"
        # Since mock_supabase.table is called with different args, we can use side_effect or just generous mocking.
        # Let's use a side_effect to return different table mocks if we want strictness, 
        # or just let the single mock handle all method chains.
        
        # The code does: supabase.table("Jobs").update(...).eq(...).execute()
        # and: supabase.table("CMDB").select(...)...
        
        # Let's ensure execute() returns something valid for select
        mock_supabase.table.return_value.select.return_value.eq.return_value.execute.return_value = mock_execute
        
        # Call the background function directly
        background_sync_task("test@example.com", "user-123", "job-123")
        
        # Verifications
        print("MOCK CALLS:", mock_supabase.table.mock_calls)
        
        # Check that we touched the Jobs table
        mock_supabase.table.assert_any_call("Jobs")
        mock_supabase.table.assert_any_call("CMDB")
        
        # Check logic:
        # Should simulate fetching existing items first
        mock_fetch.assert_called_once()


    @patch("app.api.routers.incidents.supabase")
    @patch("app.api.routers.incidents.session")  # SQS session
    def test_add_incident_creates_job(self, mock_session, mock_supabase):
        # Mock SQS
        mock_queue = MagicMock()
        mock_session.resource.return_value.get_queue_by_name.return_value = mock_queue

        # Mock Supabase
        mock_execute = MagicMock()
        mock_supabase.table.return_value.insert.return_value.execute.return_value = mock_execute

        payload = {
            "short_description": "Test Incident",
            "tag_id": "server-01",
            "source": "manual"
        }
        
        response = self.client.post("/incidents/add", json=payload)
        
        if response.status_code != 200:
            print(f"FAILED ADD RESPONSE: {response.json()}")
        self.assertEqual(response.status_code, 200)
        self.assertIn("job_id", response.json()["response"])
        
        # Verify Job creation
        mock_supabase.table.assert_any_call("Jobs")
        mock_queue.send_message.assert_called_once()
        
        # Verify SQS message has job_id
        call_args = mock_queue.send_message.call_args
        message_body = json.loads(call_args[1]['MessageBody'])
        self.assertIn("job_id", message_body["Meta"])

    @patch("app.api.routers.incidents.supabase")
    def test_analyze_incident_async(self, mock_supabase):
        # Mock fetch incident
        mock_fetch = MagicMock()
        mock_fetch.data = [{"short_description": "Server crash"}]
        mock_supabase.from_.return_value.select.return_value.eq.return_value.execute.return_value = mock_fetch
        
        # Mock Job creation
        mock_insert = MagicMock()
        mock_supabase.table.return_value.insert.return_value.execute.return_value = mock_insert

        response = self.client.post("/incidents/INC-123/analyze")
        
        if response.status_code != 200:
            print(f"FAILED ANALYZE RESPONSE: {response.json()}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "success")
        self.assertIn("job_id", response.json())
        
        # Verify Job insert
        mock_supabase.table.assert_any_call("Jobs")

if __name__ == "__main__":
    unittest.main()
