import sys
import os
import unittest
from unittest.mock import MagicMock, patch
from fastapi import FastAPI
from fastapi.testclient import TestClient

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# --- MOCKS ---
# Mock modules that integrations.py imports but we don't want to load fully or don't exist in test env
sys.modules["app.core.logger"] = MagicMock()
sys.modules["app.integrations.servicenow"] = MagicMock()
sys.modules["app.core.encryption"] = MagicMock()

# Mock verify_token
mock_verify_token = MagicMock()
mock_verify_token.return_value = {"email": "test@example.com", "user_id": "123"}

# Mock security module
security_mock = MagicMock()
security_mock.verify_token = mock_verify_token
sys.modules["app.core.security"] = security_mock

# Now import the router
from app.api.routers.integrations import router

class TestObservabilityEndpoints(unittest.TestCase):
    def setUp(self):
        # Create a minimal app
        self.app = FastAPI()
        self.app.include_router(router, prefix="/api/v1/integrations")
        self.client = TestClient(self.app)
        
        # Override dependency on the app/router
        # Since we mocked the module 'app.core.security' and its verify_token, 
        # the router definition used that mock as a default value for Depends().
        # However, FastAPI evaluates Depends at definition time.
        # Let's ensure the overrides are set just in case.
        self.app.dependency_overrides[mock_verify_token] = lambda: {"email": "test@example.com"}

    def test_datadog_config_flow(self):
        # 1. Post Config
        payload = {
            "api_key": "1234567890",
            "app_key": "abcdefghij",
            "site": "datadoghq.eu"
        }
        res = self.client.post("/api/v1/integrations/datadog/config", json=payload)
        self.assertEqual(res.status_code, 200)
        
        # 2. Get Config
        res = self.client.get("/api/v1/integrations/datadog/config")
        self.assertEqual(res.status_code, 200)
        data = res.json().get("response", {})
        self.assertEqual(data.get("site"), "datadoghq.eu")
        self.assertTrue(data.get("api_key", "").startswith("****"))
        self.assertTrue(data.get("app_key", "").startswith("****"))
        print("PASS: Datadog config flow")

    def test_prometheus_config_flow(self):
        # 1. Post Config
        payload = {
            "base_url": "http://my-prom:9090",
            "auth_type": "bearer",
            "bearer_token": "secret-token-value"
        }
        res = self.client.post("/api/v1/integrations/prometheus/config", json=payload)
        self.assertEqual(res.status_code, 200)
        
        # 2. Get Config
        res = self.client.get("/api/v1/integrations/prometheus/config")
        self.assertEqual(res.status_code, 200)
        data = res.json().get("response", {})
        self.assertEqual(data.get("base_url"), "http://my-prom:9090")
        self.assertEqual(data.get("auth_type"), "bearer")
        self.assertTrue(data.get("bearer_token", "").startswith("****"))
        print("PASS: Prometheus config flow")

if __name__ == "__main__":
    unittest.main()
