from pydantic import BaseModel
from typing import Optional

class SlackConfig(BaseModel):
    slack_bot_token: str
    slack_channel: Optional[str] = None

class EmailConfig(BaseModel):
    smtp_server: str = "smtp.gmail.com"
    smtp_port: int = 587
    sender_email: str
    sender_password: str

class GitHubConfig(BaseModel):
    """GitHub MCP configuration model.
    
    Credentials are stored in Infisical with user-scoped keys:
    - GITHUB_TOKEN: GitHub personal access token
    - GITHUB_BASE_URL: GitHub API base URL (for GitHub Enterprise)
    - GITHUB_DEFAULT_OWNER: Default GitHub owner/organization
    - GITHUB_DEFAULT_REPO: Default GitHub repository
    """
    token: Optional[str] = None
    base_url: Optional[str] = None  # For GitHub Enterprise, defaults to https://api.github.com
    default_owner: Optional[str] = None
    default_repo: Optional[str] = None
