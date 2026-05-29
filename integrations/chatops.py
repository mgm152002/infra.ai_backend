import requests
import json
from enum import Enum
from typing import Dict, Any, Optional
from app.core.config import settings
from app.core.logger import logger

class ChannelType(Enum):
    SLACK = "slack"
    TEAMS = "teams"

class ChatOpsService:
    def __init__(self):
        # We might load these from DB per organization in real enterprise app
        self.slack_webhook_url = settings.SLACK_WEBHOOK_URL if hasattr(settings, 'SLACK_WEBHOOK_URL') else None

    def send_message(self, message: str, channel: str = "#general", type: ChannelType = ChannelType.SLACK) -> bool:
        """
        Send a message to a chat channel.
        Currently simple webhook implementation.
        """
        if type == ChannelType.SLACK:
            return self._send_slack(message, channel)
        return False

    def _send_slack(self, message: str, channel: str) -> bool:
        if not self.slack_webhook_url:
            logger.warning("Slack webhook URL not configured.")
            return False
        
        payload = {
            "text": message,
            "channel": channel
        }
        
        try:
            response = requests.post(self.slack_webhook_url, json=payload)
            if response.status_code != 200:
                logger.error(f"Failed to send Slack message: {response.text}")
                return False
            return True
        except Exception as e:
            logger.error(f"ChatOps Error: {e}")
            return False

    def notify_incident(self, incident: Dict[str, Any]):
        """
        Format and send an incident notification.
        """
        msg = f"*New Incident Created*\n*ID:* {incident.get('inc_number')}\n*Description:* {incident.get('short_description')}\n*Priority:* {incident.get('priority', 'Unknown')}"
        self.send_message(msg)

chatops = ChatOpsService()
