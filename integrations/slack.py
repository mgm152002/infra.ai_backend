import os
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

from .infisical import get_secret, sanitize_email_for_secret


def _read_secret(secret_name: str) -> str:
    try:
        return get_secret(secret_name)
    except Exception:
        return None


def _get_slack_token(user_email: str = None) -> str:
    """Fetch Slack bot token from Infisical, fallback to env var.
    
    Args:
        user_email: User's email to fetch user-scoped secret. If not provided,
                   falls back to global secret for backwards compatibility.
    """
    # Try user-scoped keys first.
    if user_email:
        candidate_emails = [user_email]
        sanitized_email = sanitize_email_for_secret(user_email)
        if sanitized_email and sanitized_email != user_email:
            candidate_emails.append(sanitized_email)
        for email_key in candidate_emails:
            token = _read_secret(f"SLACK_BOT_TOKEN_{email_key}")
            if token:
                return token
    
    token = _read_secret("SLACK_BOT_TOKEN")
    if token:
        return token
    
    return os.environ.get("SLACK_BOT_TOKEN")


def _get_slack_channel(user_email: str = None) -> str:
    """Fetch Slack channel from Infisical, fallback to env var.
    
    Args:
        user_email: User's email to fetch user-scoped secret. If not provided,
                   falls back to global secret for backwards compatibility.
    """
    # Try user-scoped keys first.
    if user_email:
        candidate_emails = [user_email]
        sanitized_email = sanitize_email_for_secret(user_email)
        if sanitized_email and sanitized_email != user_email:
            candidate_emails.append(sanitized_email)
        for email_key in candidate_emails:
            channel = (
                _read_secret(f"SLACK_CHANNEL_{email_key}")
                or _read_secret(f"SLACK_DEFAULT_CHANNEL_{email_key}")
            )
            if channel:
                return channel
    
    channel = _read_secret("SLACK_CHANNEL") or _read_secret("SLACK_DEFAULT_CHANNEL")
    if channel:
        return channel
    
    return (
        os.environ.get("SLACK_CHANNEL")
        or os.environ.get("SLACK_DEFAULT_CHANNEL")
        or "#incidents"
    )


class SlackIntegration:
    def __init__(self, token: str = None, user_email: str = None):
        # Prefer passed token, otherwise fetch from Infisical/env
        self.token = token or _get_slack_token(user_email)
        self.channel = _get_slack_channel(user_email)
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
