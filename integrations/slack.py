import os
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

class SlackIntegration:
    def __init__(self, token: str = None):
        # Prefer passed token, otherwise env var
        self.token = token or os.environ.get("SLACK_BOT_TOKEN")
        self.client = None
        if self.token:
            self.client = WebClient(token=self.token)

    def check_auth(self):
        """
        Verifies if the token is valid.
        """
        if not self.client:
            return False
        try:
            self.client.auth_test()
            return True
        except SlackApiError:
            return False

    def send_message(self, channel: str, text: str, blocks: list = None):
        """
        Sends a message to a Slack channel.
        """
        if not self.client:
            return {"error": "Slack token not configured"}

        try:
            response = self.client.chat_postMessage(
                channel=channel,
                text=text,
                blocks=blocks
            )
            return {"ok": True, "ts": response["ts"]}
        except SlackApiError as e:
            return {"ok": False, "error": str(e)}

    def send_thread_reply(self, channel: str, thread_ts: str, text: str, blocks: list = None):
        """
        Sends a reply to a specific thread in a Slack channel.
        """
        if not self.client:
            return {"error": "Slack token not configured"}

        try:
            response = self.client.chat_postMessage(
                channel=channel,
                text=text,
                blocks=blocks,
                thread_ts=thread_ts
            )
            return {"ok": True, "ts": response["ts"]}
        except SlackApiError as e:
            return {"ok": False, "error": str(e)}

    def update_message(self, channel: str, ts: str, text: str, blocks: list = None):
        """
        Updates an existing message in a Slack channel.
        """
        if not self.client:
            return {"error": "Slack token not configured"}

        try:
            response = self.client.chat_update(
                channel=channel,
                ts=ts,
                text=text,
                blocks=blocks
            )
            return {"ok": True, "ts": response["ts"]}
        except SlackApiError as e:
            return {"ok": False, "error": str(e)}

    def get_users(self):
        """
        Fetches list of users in the workspace.
        """
        if not self.client:
             return []
        try:
            result = self.client.users_list()
            return result.get("members", [])
        except SlackApiError:
            return []

# Singleton instance if env var is present
slack_client = SlackIntegration()
