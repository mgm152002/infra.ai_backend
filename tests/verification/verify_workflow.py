import requests
import json
import os
from dotenv import load_dotenv

load_dotenv()

API_URL = "http://localhost:8000/api/v1/workflow"

def test_alert_types():
    print("Testing Alert Types...")
    # Create
    payload = {"name": "Test Alert", "priority": "high", "description": "This is a test alert"}
    try:
        res = requests.post(f"{API_URL}/alert-types", json=payload)
        if res.status_code == 200:
            print("  [PASS] Create Alert Type")
            data = res.json()
            # print(data)
        else:
            print(f"  [FAIL] Create Alert Type: {res.status_code} {res.text}")
    except Exception as e:
        print(f"  [FAIL] Create Alert Type: {e}")

    # List
    try:
        res = requests.get(f"{API_URL}/alert-types")
        if res.status_code == 200:
            print(f"  [PASS] List Alert Types: Found {len(res.json())} types")
        else:
            print(f"  [FAIL] List Alert Types: {res.status_code}")
    except Exception as e:
        print(f"  [FAIL] List Alert Types: {e}")

def test_change_management():
    print("\nTesting Change Management...")
    # Create
    payload = {
        "title": "Upgrade DB", 
        "description": "Upgrading postgres", 
        "requester_id": "test_user",
        "priority": "high",
        "scheduled_at": "2023-12-25T10:00:00"
    }
    try:
        res = requests.post(f"{API_URL}/change-requests", json=payload)
        if res.status_code == 200:
            print("  [PASS] Create Change Request")
            # print(res.json())
        else:
             print(f"  [FAIL] Create Change Request: {res.status_code} {res.text}")
    except Exception as e:
        print(f"  [FAIL] Create Change Request: {e}")

if __name__ == "__main__":
    print("Starting Verification...")
    # Note: Requires backend to be running.
    # checking if backend is reachable
    try:
        requests.get("http://localhost:8000/docs")
        test_alert_types()
        test_change_management()
    except:
        print("Backend not running or not reachable. Skipping live verification.")
