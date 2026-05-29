import os
import requests
import json
import re
from typing import Dict, Any, Optional, List
from requests.auth import HTTPBasicAuth
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser
from langchain_core.runnables import Runnable

from app.core.config import settings
from app.core.llm import get_llm
from app.core.logger import logger

class ServiceNowIntegration:
    """
    Handles interactions with ServiceNow, including credential retrieval from Infisical
    and incident management.
    """
    
    SYS_ID_MAPPING = {
        "state": {
            "new": 1,
            "in_progress": 2,
            "on_hold": 3,
            "resolved": 6,
            "closed": 7,
            "canceled": 8
        },
        "impact": {"low": 3, "medium": 2, "high": 1},
        "urgency": {"low": 3, "medium": 2, "high": 1},
    }

    def _get_credentials_from_infisical(self, mail: str) -> Dict[str, str]:
        """
        Retrieves user-specific ServiceNow credentials from Infisical.
        
        NOTE: This legacy auth flow matches the original main.py logic. 
         Ideally, we should unify secrets management.
        """
        secret_auth_uri = "https://app.infisical.com/api/v1/auth/universal-auth/login"
        auth_data = {
            "clientId": settings.INFISICAL_CLIENT_ID,
            "clientSecret": settings.INFISICAL_CLIENT_SECRET
        }
        
        try:
            # Login to Infisical
            response = requests.post(secret_auth_uri, data=auth_data)
            response.raise_for_status()
            access_token = response.json()['accessToken']
            
            headers = {'Authorization': f'Bearer {access_token}'}
            base_url = 'https://us.infisical.com/api/v3/secrets/raw'
            
            # Helper to fetch a single secret
            def get_secret(name):
                url = f"{base_url}/{name}_{mail}?workspaceSlug=infraai-oqb-h&environment=prod"
                r = requests.get(url, headers=headers)
                r.raise_for_status()
                return r.json()['secret']['secretValue']

            return {
                "snow_key": get_secret("SNOW_KEY"),
                "snow_instance": get_secret("SNOW_INSTANCE"),
                "snow_user": get_secret("SNOW_USER"),
                "snow_password": get_secret("SNOW_PASSWORD"),
            }
        except Exception as e:
            logger.error(f"Failed to fetch ServiceNow credentials for {mail}: {e}")
            raise Exception("Could not retrieve ServiceNow credentials")

    def create_incident(self, create_data: Dict[str, Any], mail: str) -> Dict[str, Any]:
        creds = self._get_credentials_from_infisical(mail)
        instance = creds['snow_instance']
        if not instance.startswith('http'):
            instance = f"https://{instance}"
        base_url = f"{instance}/api/now/table/incident"
        
        headers = {
            "Content-Type": "application/json",
            "x-sn-apikey": creds['snow_key']
        }

        # Use LLM to format payload (keeping existing logic)
        prompt = f"""
        Generate a ServiceNow REST API JSON body for creating an incident.
        Input data: {create_data}
        Mappings: {self.SYS_ID_MAPPING}
        Requirements:
        1. Use numeric values for urgency/impact based on priority if needed.
        2. Return ONLY valid JSON.
        """
        llm_response = get_llm().invoke(prompt).content
        
        try:
            # Extract JSON from potential markdown code blocks
            match = re.search(r'\{.*\}', llm_response, re.DOTALL)
            if match:
                payload = json.loads(match.group())
            else:
                payload = json.loads(llm_response)
                
            # Ensure impact/urgency are ints
            if 'urgency' in payload: payload['urgency'] = int(payload['urgency'])
            if 'impact' in payload: payload['impact'] = int(payload['impact'])

            response = requests.post(base_url, json=payload, headers=headers)
            
            if response.status_code == 201:
                return response.json()
            else:
                return {"status": "failed", "message": response.text}

        except Exception as e:
            logger.error(f"Error creating ServiceNow incident: {e}")
            return {"status": "error", "message": str(e)}

    def get_incident(self, incident_number: str, mail: str) -> Dict[str, Any]:
        creds = self._get_credentials_from_infisical(mail)
        base_url = f"{creds['snow_instance']}/api/now/table/incident"
        
        query_url = f"{base_url}?sysparm_limit=1&number={incident_number}"
        
        response = requests.get(
            query_url, 
            auth=HTTPBasicAuth(creds['snow_user'], creds['snow_password'])
        )
        
        if response.status_code == 200:
            results = response.json().get('result', [])
            return results[0] if results else None
        else:
            logger.error(f"ServiceNow API Error: {response.text}")
            return None

    def update_incident(self, incident_number: str, updates: Dict[str, Any], mail: str) -> Dict[str, Any]:
        creds = self._get_credentials_from_infisical(mail)
        base_url = f"{creds['snow_instance']}/api/now/table/incident"
        
        # First get sys_id
        incident = self.get_incident(incident_number, mail)
        if not incident:
            return {"status": "failed", "message": "Incident not found"}
            
        sys_id = incident['sys_id']
        update_url = f"{base_url}/{sys_id}"
        
        # LLM for payload formatting
        prompt = f"""
        Generate a ServiceNow REST API JSON body for updating an incident.
        Updates: {updates}
        Mappings: {self.SYS_ID_MAPPING}
        Instructions:
        - If closing, include 'close_code' and 'close_notes'.
        - return ONLY JSON.
        """
        llm_response = get_llm().invoke(prompt).content
        
        try:
            match = re.search(r'\{.*\}', llm_response, re.DOTALL)
            if match:
                payload = json.loads(match.group())
            else:
                payload = json.loads(llm_response)

            headers = {
                "Content-Type": "application/json",
                "x-sn-apikey": creds['snow_key']
            }
            
            response = requests.patch(update_url, json=payload, headers=headers)
            return response.json() if response.status_code == 200 else {"status": "failed", "message": response.text}
            
        except Exception as e:
             return {"status": "error", "message": str(e)}

    def fetch_cmdb_assets(self, mail: str, batch_size: int = 100) -> List[Dict[str, Any]]:
        """
        Fetch CI items from ServiceNow's cmdb_ci table with pagination.
        """
        creds = self._get_credentials_from_infisical(mail)
        instance = creds['snow_instance']
        if not instance.startswith('http'):
            instance = f"https://{instance}"
        base_url = f"{instance}/api/now/table/cmdb_ci"
        
        all_assets = []
        offset = 0
        more_results = True
        
        # Extended fields for robust data model
        fields = [
            "sys_id", "name", "ip_address", "os", "short_description", "sys_class_name",
            "manufacturer", "model_id", "serial_number", "mac_address", 
            "location", "install_status", "assigned_to"
        ]
        
        while more_results:
            query_params = {
                "sysparm_limit": batch_size,
                "sysparm_offset": offset,
                "sysparm_fields": ",".join(fields),
                "sysparm_exclude_reference_link": "true",
                "sysparm_display_value": "true" 
            }
            
            try:
                response = requests.get(
                    base_url, 
                    auth=HTTPBasicAuth(creds['snow_user'], creds['snow_password']),
                    params=query_params
                )
                
                if response.status_code == 200:
                    results = response.json().get('result', [])
                    if results:
                        all_assets.extend(results)
                        offset += batch_size
                        # Stop if we got fewer items than requested
                        if len(results) < batch_size:
                            more_results = False
                    else:
                        more_results = False
                else:
                    logger.error(f"ServiceNow CMDB fetch failed: {response.text}")
                    if offset == 0:
                        raise Exception(f"Failed to fetch assets: {response.status_code}")
                    break
            except Exception as e:
                logger.error(f"Exception during CMDB fetch at offset {offset}: {e}")
                if offset == 0:
                    raise
                break
                
        return all_assets

servicenow_client = ServiceNowIntegration()
