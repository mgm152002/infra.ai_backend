import os
from typing import Any, Dict, Optional, Tuple

import requests


INFISICAL_AUTH_URL = "https://app.infisical.com/api/v1/auth/universal-auth/login"
INFISICAL_API_BASE_URL = "https://us.infisical.com/api/v3"

DEFAULT_WORKSPACE_ID = os.getenv("INFISICAL_WORKSPACE_ID", "113f5a41-dbc3-447d-8b3a-6fe8e9e6e99c")
DEFAULT_WORKSPACE_SLUG = os.getenv("INFISICAL_WORKSPACE_SLUG", "infraai-oqb-h")
DEFAULT_ENVIRONMENT = os.getenv("INFISICAL_ENVIRONMENT", "prod")


class InfisicalError(RuntimeError):
    pass


def _parse_secret_value(payload: Any) -> Optional[str]:
    """Parse Infisical secret responses across versions/shapes.

    Known shapes in this repo:
    - {"secret": {"secretValue": "..."}}
    - [{"secret": {"secretValue": "..."}}]
    """
    if payload is None:
        return None
    if isinstance(payload, dict):
        secret = payload.get("secret")
        if isinstance(secret, dict):
            val = secret.get("secretValue")
            return str(val) if val is not None else None
    if isinstance(payload, list) and payload:
        first = payload[0]
        if isinstance(first, dict):
            secret = first.get("secret")
            if isinstance(secret, dict):
                val = secret.get("secretValue")
                return str(val) if val is not None else None
    return None


def infisical_login(*, timeout_s: int = 20) -> str:
    client_id = os.getenv("clientId")
    client_secret = os.getenv("clientSecret")
    if not client_id or not client_secret:
        raise InfisicalError("Infisical universal-auth credentials are not configured (clientId/clientSecret env vars missing)")

    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    auth_data = {"clientId": client_id, "clientSecret": client_secret}

    resp = requests.post(INFISICAL_AUTH_URL, headers=headers, data=auth_data, timeout=timeout_s)
    resp.raise_for_status()
    token = (resp.json() or {}).get("accessToken")
    if not token:
        raise InfisicalError("Infisical login did not return accessToken")
    return token


def get_secret(
    secret_name: str,
    *,
    workspace_slug: str = DEFAULT_WORKSPACE_SLUG,
    environment: str = DEFAULT_ENVIRONMENT,
    access_token: Optional[str] = None,
    timeout_s: int = 20,
) -> Optional[str]:
    if not secret_name:
        return None

    token = access_token or infisical_login(timeout_s=timeout_s)
    url = f"{INFISICAL_API_BASE_URL}/secrets/raw/{secret_name}"
    params = {"workspaceSlug": workspace_slug, "environment": environment}

    resp = requests.get(url, headers={"Authorization": f"Bearer {token}"}, params=params, timeout=timeout_s)
    if resp.status_code == 404:
        return None
    resp.raise_for_status()

    return _parse_secret_value(resp.json())


def set_secret(
    secret_name: str,
    secret_value: str,
    *,
    workspace_id: str = DEFAULT_WORKSPACE_ID,
    environment: str = DEFAULT_ENVIRONMENT,
    access_token: Optional[str] = None,
    timeout_s: int = 20,
) -> None:
    if not secret_name:
        raise ValueError("secret_name is required")

    token = access_token or infisical_login(timeout_s=timeout_s)
    url = f"{INFISICAL_API_BASE_URL}/secrets/raw/{secret_name}"

    payload: Dict[str, Any] = {
        "environment": environment,
        "secretValue": secret_value,
        "workspaceId": workspace_id,
    }

    resp = requests.post(
        url,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json=payload,
        timeout=timeout_s,
    )
    resp.raise_for_status()


def user_scoped_secret(prefix: str, mail: str) -> str:
    if not prefix or not mail:
        raise ValueError("prefix and mail are required")
    return f"{prefix}_{mail}"


def get_many(
    mail: str,
    keys: Tuple[str, ...],
    *,
    access_token: Optional[str] = None,
    workspace_slug: str = DEFAULT_WORKSPACE_SLUG,
    environment: str = DEFAULT_ENVIRONMENT,
) -> Dict[str, Optional[str]]:
    """Convenience helper: load multiple secrets under the same access token."""
    token = access_token or infisical_login()
    out: Dict[str, Optional[str]] = {}
    for key in keys:
        out[key] = get_secret(user_scoped_secret(key, mail), access_token=token, workspace_slug=workspace_slug, environment=environment)
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
        set_secret(user_scoped_secret(key, mail), str(value), access_token=token, workspace_id=workspace_id, environment=environment)
