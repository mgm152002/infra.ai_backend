from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
import os
import requests
from app.core.config import settings
from app.core.logger import logger

class ObservabilityProvider(ABC):
    @abstractmethod
    def get_metrics(self, query: str) -> Dict[str, Any]:
        """Fetch metrics from the provider."""
        pass

    @abstractmethod
    def health_check(self) -> bool:
        """Check connection to the provider."""
        pass

class PrometheusProvider(ObservabilityProvider):
    def __init__(self, base_url: str):
        self.base_url = base_url

    def get_metrics(self, query: str) -> Dict[str, Any]:
        try:
            response = requests.get(f"{self.base_url}/api/v1/query", params={"query": query})
            return response.json()
        except Exception as e:
            logger.error(f"Prometheus query failed: {e}")
            return {"status": "error", "message": str(e)}

    def health_check(self) -> bool:
        try:
            requests.get(f"{self.base_url}/-/healthy")
            return True
        except:
            return False

class DatadogProvider(ObservabilityProvider):
    def __init__(self, api_key: str, app_key: str):
        self.api_key = api_key
        self.app_key = app_key
        self.base_url = "https://api.datadoghq.com/api/v1"

    def get_metrics(self, query: str) -> Dict[str, Any]:
        """
        Query Datadog metrics (impl stub).
        Docs: https://docs.datadoghq.com/api/latest/metrics/#query-metrics
        """
        headers = {
            "DD-API-KEY": self.api_key,
            "DD-APPLICATION-KEY": self.app_key
        }
        # Time window would be dynamic in production
        params = {
            "from": "now-1h",
            "to": "now",
            "query": query
        }
        try:
            response = requests.get(f"{self.base_url}/query", headers=headers, params=params)
            return response.json()
        except Exception as e:
             logger.error(f"Datadog query failed: {e}")
             return {"status": "error", "message": str(e)}

    def health_check(self) -> bool:
        # Stub: Just check if keys are present
        return bool(self.api_key and self.app_key)

class ObservabilityFactory:
    _instances: Dict[str, ObservabilityProvider] = {}

    @classmethod
    def get_provider(cls, name: str = "prometheus") -> ObservabilityProvider:
        if name in cls._instances:
            return cls._instances[name]
        
        if name == "prometheus":
            # Default to localhost if not set
            url = os.getenv("PROMETHEUS_URL", "http://localhost:9090")
            instance = PrometheusProvider(url)
        elif name == "datadog":
            instance = DatadogProvider(
                api_key=os.getenv("DD_API_KEY", ""),
                app_key=os.getenv("DD_APP_KEY", "")
            )
        else:
            raise ValueError(f"Unknown provider: {name}")
            
        cls._instances[name] = instance
        return instance
