import sys
import os
import unittest
from unittest.mock import MagicMock, patch

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Mock dependencies
sys.modules["app.core.security"] = MagicMock()
sys.modules["app.db.session"] = MagicMock()

class TestAdminEndpoints(unittest.TestCase):
    
    def test_health_check(self):
        """Verify health check endpoint logic."""
        from app.api.routers.admin import system_health
        
        # Mock dependencies just for the function call
        result = system_health(user_data={}, _=True)
        self.assertEqual(result['status'], 'healthy')
        self.assertIn('database', result['services'])
        print("PASS: Admin Health Check")

    def test_list_users(self):
        """Verify list users logic (mocked DB)."""
        from app.api.routers.admin import list_users, supabase
        
        # Mock DB response
        mock_response = MagicMock()
        mock_response.data = [{"id": 1, "email": "test@example.com"}]
        supabase.table.return_value.select.return_value.execute.return_value = mock_response
        
        result = list_users(user_data={}, _=True)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['email'], "test@example.com")
        print("PASS: Admin List Users")

if __name__ == "__main__":
    unittest.main()
