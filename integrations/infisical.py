import os
import time
from typing import Any, Dict, Optional, Tuple
from urllib.parse import quote

import requests
from requests.exceptions import ConnectionError as RequestsConnectionError
from requests.exceptions import ReadTimeout, Timeout


INFISICAL_AUTH_URL = "https://app.infisical.com/api/v1/auth/universal-auth/login"
INFISICAL_API_BASE_URL = "https://us.infisical.com/api/v3"

DEFAULT_WORKSPACE_ID = os.getenv("INFISICAL_WORKSPACE_ID", "113f5a41-dbc3-447d-8b3a-6fe8e9e6e99c")
DEFAULT_WORKSPACE_SLUG = os.getenv("INFISICAL_WORKSPACE_SLUG", "infraai-oqb-h")
DEFAULT_ENVIRONMENT = os.getenv("INFISICAL_ENVIRONMENT", "prod")

# Retry configuration for transient network errors
MAX_RETRIES = 3
RETRY_BACKOFF_FACTOR = 2  # Exponential backoff: 1s, 2s, 4s


class InfisicalError(RuntimeError):
    pass


class InfisicalConnectionError(InfisicalError):
    """Raised when connection to Infisical fails after all retries."""
    pass


def _parse_secret_value(payload: Any) -> Optional[str]:
    """Parse Infisical secret responses across versions/shapes.

    Known shapes in this repo:
    - {"secret": {"secretValue": "..."}}
    - [{"secret": {"secretValue": "..."}}]
    """
    # Removed spammy debug log
    
    if payload is None:
        return None
    
    # Handle array format: [{"secret": {"secretValue": "..."}}]
    if isinstance(payload, list) and payload:
        first = payload[0]
        if isinstance(first, dict):
            secret = first.get("secret")
            if isinstance(secret, dict):
                val = secret.get("secretValue")
                # Removed spammy debug log
                return str(val) if val is not None else None
    
    # Handle direct dict format: {"secret": {"secretValue": "..."}}
    if isinstance(payload, dict):
        secret = payload.get("secret")
        if isinstance(secret, dict):
            val = secret.get("secretValue")
            # Removed spammy debug log
            return str(val) if val is not None else None
        
        # Handle direct secretValue format (some Infisical responses)
        val = payload.get("secretValue")
        if val is not None:
            return str(val)
    
    return None


def infisical_login(*, timeout_s: int = 20) -> str:
    """Authenticate with Infisical using universal-auth.
    
    Implements retry logic with exponential backoff for transient network errors.
    """
    client_id = os.getenv("clientId")
    client_secret = os.getenv("clientSecret")
    if not client_id or not client_secret:
        raise InfisicalError("Infisical universal-auth credentials are not configured (clientId/clientSecret env vars missing)")

    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    auth_data = {"clientId": client_id, "clientSecret": client_secret}
    
    last_error = None
    
    for attempt in range(MAX_RETRIES):
        try:
            resp = requests.post(INFISICAL_AUTH_URL, headers=headers, data=auth_data, timeout=timeout_s)
            resp.raise_for_status()
            token = (resp.json() or {}).get("accessToken")
            if not token:
                raise InfisicalError("Infisical login did not return accessToken")
            return token
        except (RequestsConnectionError, ReadTimeout, Timeout) as e:
            last_error = e
            if attempt < MAX_RETRIES - 1:
                wait_time = RETRY_BACKOFF_FACTOR ** attempt
                time.sleep(wait_time)
                continue
            # All retries exhausted
            raise InfisicalConnectionError(
                f"Failed to connect to Infisical after {MAX_RETRIES} attempts: {type(e).__name__}: {e}"
            ) from last_error
        except requests.exceptions.HTTPError as e:
            # Don't retry HTTP errors (like 401 Unauthorized) - they indicate auth issues
            raise InfisicalError(f"Infisical authentication failed: {e}") from e

    # Should not reach here, but just in case
    raise InfisicalConnectionError(
        f"Failed to connect to Infisical after {MAX_RETRIES} attempts: {last_error}"
    )


def get_secret(
    secret_name: str,
    *,
    workspace_slug: str = DEFAULT_WORKSPACE_SLUG,
    environment: str = DEFAULT_ENVIRONMENT,
    access_token: Optional[str] = None,
    timeout_s: int = 20,
) -> Optional[str]:
    """Retrieve a secret from Infisical.
    
    Implements retry logic with exponential backoff for transient network errors.
    """
    if not secret_name:
        return None

    token = access_token or infisical_login(timeout_s=timeout_s)
    # URL-encode the secret name to handle special characters like @ in email addresses
    encoded_secret_name = quote(secret_name, safe='')
    url = f"{INFISICAL_API_BASE_URL}/secrets/raw/{encoded_secret_name}"
    params = {"workspaceSlug": workspace_slug, "environment": environment}
    
    last_error = None
    
    for attempt in range(MAX_RETRIES):
        try:
            resp = requests.get(url, headers={"Authorization": f"Bearer {token}"}, params=params, timeout=timeout_s)
            if resp.status_code == 404:
                return None
            resp.raise_for_status()

            result = _parse_secret_value(resp.json())
            return result
        except (RequestsConnectionError, ReadTimeout, Timeout) as e:
            last_error = e
            if attempt < MAX_RETRIES - 1:
                wait_time = RETRY_BACKOFF_FACTOR ** attempt
                time.sleep(wait_time)
                continue
            # All retries exhausted
            raise InfisicalConnectionError(
                f"Failed to retrieve secret '{secret_name}' from Infisical after {MAX_RETRIES} attempts: {type(e).__name__}: {e}"
            ) from last_error
        except requests.exceptions.HTTPError as e:
            raise InfisicalError(f"Failed to retrieve secret '{secret_name}' from Infisical: {e}") from e

    return None


def get_default_slack_channel() -> Optional[str]:
    """Get the default Slack channel from Infisical secrets."""
    channel = get_secret("SLACK_DEFAULT_CHANNEL") or get_secret("SLACK_CHANNEL")
    if channel:
        return channel
    return (
        os.environ.get("SLACK_DEFAULT_CHANNEL")
        or os.environ.get("SLACK_CHANNEL")
        or "#incidents"
    )


def set_secret(
    secret_name: str,
    secret_value: str,
    *,
    workspace_id: str = DEFAULT_WORKSPACE_ID,
    environment: str = DEFAULT_ENVIRONMENT,
    access_token: Optional[str] = None,
    timeout_s: int = 20,
) -> None:
    """Set a secret in Infisical.
    
    Implements retry logic with exponential backoff for transient network errors.
    """
    if not secret_name:
        raise ValueError("secret_name is required")

    token = access_token or infisical_login(timeout_s=timeout_s)
    # URL-encode the secret name to handle special characters like @ in email addresses
    encoded_secret_name = quote(secret_name, safe='')
    url = f"{INFISICAL_API_BASE_URL}/secrets/raw/{encoded_secret_name}"

    payload: Dict[str, Any] = {
        "environment": environment,
        "secretValue": secret_value,
        "workspaceId": workspace_id,
    }

    # Removed debug logs

    # Try PUT first - works for both create and update in Infisical v3
    last_error = None
    
    for attempt in range(MAX_RETRIES):
        try:
            resp = requests.put(
                url,
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                json=payload,
                timeout=timeout_s,
            )

            

            
            if resp.status_code == 404:
                resp = requests.post(
                    url,
                    headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                    json=payload,
                    timeout=timeout_s,
                )
            
            if resp.status_code >= 400:
                pass
            
            resp.raise_for_status()
            return  # Success
        except (RequestsConnectionError, ReadTimeout, Timeout) as e:
            last_error = e
            if attempt < MAX_RETRIES - 1:
                wait_time = RETRY_BACKOFF_FACTOR ** attempt
                time.sleep(wait_time)
                continue
            # All retries exhausted
            raise InfisicalConnectionError(
                f"Failed to set secret '{secret_name}' in Infisical after {MAX_RETRIES} attempts: {type(e).__name__}: {e}"
            ) from last_error
        except requests.exceptions.HTTPError as e:
            raise InfisicalError(f"Failed to set secret '{secret_name}' in Infisical: {e}") from e

    # Should not reach here
    raise InfisicalConnectionError(
        f"Failed to set secret '{secret_name}' in Infisical after {MAX_RETRIES} attempts: {last_error}"
    )


def user_scoped_secret(prefix: str, mail: str) -> str:
    if not prefix or not mail:
        raise ValueError("prefix and mail are required")
    # Use full email without sanitization
    result = f"{prefix}_{mail}"
    return result


def sanitize_email_for_secret(email: str) -> str:
    """
    Sanitize email for use in Infisical secret names.
    Replaces @ with _AT_ to avoid URL encoding issues and potential API problems.
    """
    if not email:
        return email
    # Replace @ with _AT_ to make it safe for secret names
    return email.replace("@", "_AT_")


def get_many(
    mail: str,
    keys: Tuple[str, ...],
    *,
    access_token: Optional[str] = None,
    workspace_slug: str = DEFAULT_WORKSPACE_SLUG,
    environment: str = DEFAULT_ENVIRONMENT,
) -> Dict[str, Optional[str]]:
    """Convenience helper: load multiple secrets under the same access token.
    
    Tries full email format first, then falls back to sanitized format for backwards compatibility.
    """
    
    
    token = access_token or infisical_login()
    out: Dict[str, Optional[str]] = {}
    
    # Try full email format first
    for key in keys:
        secret_name = user_scoped_secret(key, mail)
        value = get_secret(secret_name, access_token=token, workspace_slug=workspace_slug, environment=environment)
        
        # If not found with full email, try sanitized format for backwards compatibility
        if value is None:
            sanitized_mail = sanitize_email_for_secret(mail)
            if sanitized_mail != mail:
                sanitized_secret_name = f"{key}_{sanitized_mail}"
                value = get_secret(sanitized_secret_name, access_token=token, workspace_slug=workspace_slug, environment=environment)
        
        out[key] = value
    
    return out


def set_many(
    mail: str,
    values: Dict[str, Optional[str]],
    *,
    access_token: Optional[str] = None,
    workspace_id: str = DEFAULT_WORKSPACE_ID,
    environment: str = DEFAULT_ENVIRONMENT,
) -> None:
    """Convenience helper: store multiple secrets under the same access token."""
    token = access_token or infisical_login()
    for key, value in values.items():
        if value is None:
            continue
        secret_name = user_scoped_secret(key, mail)
        set_secret(secret_name, str(value), access_token=token, workspace_id=workspace_id, environment=environment)
