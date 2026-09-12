"""Credential and connection-configuration API routes."""

import os
import traceback
from datetime import datetime
from typing import Annotated

import jwt
import redis
import requests
from fastapi import APIRouter, Depends, HTTPException, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.config import settings
from app.core.database import supabase
from app.core.security import verify_token
from app.schemas.credentials import EmailConfig, SlackConfig
from app.schemas.models import Aws, PrometheusConfig, Snow_key, ssh
from integrations.infisical import get_many, set_many


router = APIRouter()
security = HTTPBearer()
clerk_public_key = settings.CLERK_PUBLIC_KEY
r = redis.Redis(host="localhost", port=6379, db=0)


@router.post("/uploadSSH")
def uploadSSH(credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)], ssh: ssh):

    # subprocess.run(['chmod', '600', 'key.pem'])
    secret_auth_uri = "https://app.infisical.com/api/v1/auth/universal-auth/login"

    # Proper headers format as a dictionary
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    # Proper data format for the authentication request
    auth_data = {"clientSecret": os.getenv("clientSecret"), "clientId": os.getenv("clientId")}
    try:
        token = credentials.credentials
        res = jwt.decode(token, key=clerk_public_key, algorithms=["RS256"])
        mail = res["email"]
    except jwt.DecodeError as e:
        print(e)
        return {"error": e}

    try:
        # Get access token
        response = requests.post(url=secret_auth_uri, headers=headers, data=auth_data)
        response.raise_for_status()  # Raise exception for bad status codes
        access_token = response.json()["accessToken"]

        # Headers for subsequent requests
        auth_headers = {"Authorization": f"Bearer {access_token}"}
    except:
        print("error")
    url = f"https://us.infisical.com/api/v3/secrets/raw/SSH_KEY_{mail}"

    payload = {
        "environment": "prod",
        "secretValue": ssh.key_file,
        "workspaceId": "113f5a41-dbc3-447d-8b3a-6fe8e9e6e99c",
    }

    # json_payload = json.dumps(payload)

    headers = {"Authorization": auth_headers["Authorization"], "Content-Type": "application/json"}

    response = requests.request("POST", url, json=payload, headers=headers)
    os.remove("key.pem")
    return {"response": "done"}


@router.get("/getSnowKey/{mail}")
def getSnowKeys(mail: str):
    secret_auth_uri = "https://app.infisical.com/api/v1/auth/universal-auth/login"

    # Proper headers format as a dictionary
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    # Proper data format for the authentication request
    auth_data = {"clientSecret": os.getenv("clientSecret"), "clientId": os.getenv("clientId")}

    try:
        # Get access token
        response = requests.post(url=secret_auth_uri, headers=headers, data=auth_data)
        response.raise_for_status()  # Raise exception for bad status codes
        access_token = response.json()["accessToken"]

        # Headers for subsequent requests
        auth_headers = {"Authorization": f"Bearer {access_token}"}

        # Get ServiceNow credentials
        base_url = "https://us.infisical.com/api/v3/secrets/raw"
        snow_credentials = {
            "snow_key": requests.get(
                f"{base_url}/SNOW_KEY_{mail}?workspaceSlug=infraai-oqb-h&environment=prod",
                headers=auth_headers,
            ).json(),
            "snow_instance": requests.get(
                f"{base_url}/SNOW_INSTANCE_{mail}?workspaceSlug=infraai-oqb-h&environment=prod",
                headers=auth_headers,
            ).json(),
            "snow_user": requests.get(
                f"{base_url}/SNOW_USER_{mail}?workspaceSlug=infraai-oqb-h&environment=prod",
                headers=auth_headers,
            ).json(),
            "snow_password": requests.get(
                f"{base_url}/SNOW_PASSWORD_{mail}?workspaceSlug=infraai-oqb-h&environment=prod",
                headers=auth_headers,
            ).json(),
        }
    except:
        print("error")

    snowkeys: Snow_key = {
        "snow_key": snow_credentials["snow_key"]["secret"]["secretValue"],
        "snow_instance": snow_credentials["snow_instance"]["secret"]["secretValue"],
        "snow_user": snow_credentials["snow_user"]["secret"]["secretValue"],
        "snow_password": snow_credentials["snow_password"]["secret"]["secretValue"],
    }

    return {"response": snowkeys}


@router.get("/getSSHKeys/{mail}")
def getSSHKeys(mail: str):
    secret_auth_uri = "https://app.infisical.com/api/v1/auth/universal-auth/login"

    # Proper headers format as a dictionary
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    # Proper data format for the authentication request
    auth_data = {"clientSecret": os.getenv("clientSecret"), "clientId": os.getenv("clientId")}

    try:
        # Get access token
        response = requests.post(url=secret_auth_uri, headers=headers, data=auth_data)
        response.raise_for_status()  # Raise exception for bad status codes
        access_token = response.json()["accessToken"]

        # Headers for subsequent requests
        auth_headers = {"Authorization": f"Bearer {access_token}"}

        # Get AWS credentials
        base_url = "https://us.infisical.com/api/v3/secrets/raw"
        sshkey = (
            requests.get(
                f"{base_url}/SSH_KEY_{mail}?workspaceSlug=infraai-oqb-h&environment=prod",
                headers=auth_headers,
            ).json(),
        )

        with open("key.pem", "wb") as file:
            file.write(sshkey[0]["secret"]["secretValue"].encode("utf-8"))
        return {"key_file": sshkey[0]["secret"]["secretValue"]}
    except:
        print("error")


@router.get("/getAwsKeys/{mail}")
def getAwsKeys(mail: str):
    secret_auth_uri = "https://app.infisical.com/api/v1/auth/universal-auth/login"

    # Proper headers format as a dictionary
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    # Proper data format for the authentication request
    auth_data = {"clientSecret": os.getenv("clientSecret"), "clientId": os.getenv("clientId")}

    try:
        # Get access token
        response = requests.post(url=secret_auth_uri, headers=headers, data=auth_data)
        response.raise_for_status()  # Raise exception for bad status codes
        access_token = response.json()["accessToken"]

        # Headers for subsequent requests
        auth_headers = {"Authorization": f"Bearer {access_token}"}

        # Get AWS credentials
        base_url = "https://us.infisical.com/api/v3/secrets/raw"
        aws_credentials = {
            "aws_access_key_id": requests.get(
                f"{base_url}/AWS_ACCESS_KEY_{mail}?workspaceSlug=infraai-oqb-h&environment=prod",
                headers=auth_headers,
            ).json(),
            "aws_secret_access_key": requests.get(
                f"{base_url}/AWS_SECRET_KEY_{mail}?workspaceSlug=infraai-oqb-h&environment=prod",
                headers=auth_headers,
            ).json(),
            "aws_region": requests.get(
                f"{base_url}/AWS_REGION_{mail}?workspaceSlug=infraai-oqb-h&environment=prod",
                headers=auth_headers,
            ).json(),
        }
        print(aws_credentials)
    except:
        print("error")
    awskeys: Aws = {
        "access_key": aws_credentials["aws_access_key_id"]["secret"]["secretValue"],
        "secrete_access": aws_credentials["aws_secret_access_key"]["secret"]["secretValue"],
        "region": aws_credentials["aws_region"]["secret"]["secretValue"],
    }
    return {"response": awskeys}


@router.post("/addSNOWCredentials")
def addSnowCredentials(
    snow: Snow_key,
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)],
    response: Response,
):
    secret_auth_uri = "https://app.infisical.com/api/v1/auth/universal-auth/login"

    # Proper headers format as a dictionary
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    # Proper data format for the authentication request
    auth_data = {"clientSecret": os.getenv("clientSecret"), "clientId": os.getenv("clientId")}

    try:
        token = credentials.credentials
        res = jwt.decode(token, key=clerk_public_key, algorithms=["RS256"])
        mail = res["email"]

        try:
            # Get access token
            response = requests.post(url=secret_auth_uri, headers=headers, data=auth_data)
            response.raise_for_status()  # Raise exception for bad status codes
            access_token = response.json()["accessToken"]

            # Headers for subsequent requests
            auth_headers = {"Authorization": f"Bearer {access_token}"}
        except:
            print("error")
    except jwt.DecodeError as e:
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {"message": e}

    # Create dictionary for ServiceNow credentials
    snowdict = {
        f"SNOW_KEY_{mail}": snow.snow_key,
        f"SNOW_INSTANCE_{mail}": snow.snow_instance,
        f"SNOW_USER_{mail}": snow.snow_user,
        f"SNOW_PASSWORD_{mail}": snow.snow_password,
    }

    # Add each credential to Infisical
    for key, value in snowdict.items():
        url = f"https://us.infisical.com/api/v3/secrets/raw/{key}"
        payload = {
            "environment": "prod",
            "secretValue": value,
            "workspaceId": "113f5a41-dbc3-447d-8b3a-6fe8e9e6e99c",
        }

        headers = {
            "Authorization": auth_headers["Authorization"],
            "Content-Type": "application/json",
        }

        response = requests.request("POST", url, json=payload, headers=headers)

    return {"response": "done"}


@router.post("/addAwsCredentials")
def addAwsCredentials(
    Aws: Aws,
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)],
    response: Response,
):
    secret_auth_uri = "https://app.infisical.com/api/v1/auth/universal-auth/login"

    # Proper headers format as a dictionary
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    # Proper data format for the authentication request
    auth_data = {"clientId": os.getenv("clientId"), "clientSecret": os.getenv("clientSecret")}
    try:
        token = credentials.credentials
        res = jwt.decode(token, key=clerk_public_key, algorithms=["RS256"])
        mail = res["email"]
        try:
            # Get access token
            response = requests.post(url=secret_auth_uri, headers=headers, data=auth_data)
            response.raise_for_status()  # Raise exception for bad status codes
            access_token = response.json()["accessToken"]

            # Headers for subsequent requests
            auth_headers = {"Authorization": f"Bearer {access_token}"}
        except:
            print("error")
    except jwt.DecodeError as e:
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {"message": e}

    # Create dictionary for AWS credentials - use full email
    awsdict = {
        f"AWS_ACCESS_KEY_{mail}": Aws.access_key,
        f"AWS_SECRET_KEY_{mail}": Aws.secrete_access,
        f"AWS_REGION_{mail}": Aws.region,
    }

    # Try to save credentials, if fails with 400, retry with original email
    for key, value in awsdict.items():
        url = f"https://us.infisical.com/api/v3/secrets/raw/{key}"
        payload = {
            "environment": "prod",
            "secretValue": value,
            "workspaceId": "113f5a41-dbc3-447d-8b3a-6fe8e9e6e99c",
        }
        headers = {
            "Authorization": auth_headers["Authorization"],
            "Content-Type": "application/json",
        }
        try:
            response = requests.request("POST", url, json=payload, headers=headers)
            # If we get a 400 error with sanitized email, retry with original email
            if response.status_code == 400 and "_AT_" not in key:
                print(
                    f"DEBUG addAwsCredentials: Got 400 error with key {key}, retrying with sanitized key..."
                )
                # The key is already sanitized, this shouldn't happen but just in case
                continue
        except Exception as e:
            print(f"Error saving AWS credential {key}: {e}")
            continue

    return {"response": "done"}


@router.post("/storeJwt/{jwt}")
def addJWT(jwt: str):

    r.set("userjwt", jwt)


@router.post("/updateSSH")
async def update_ssh_credentials(
    ssh: ssh, credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)]
):
    try:
        token = credentials.credentials
        res = jwt.decode(token, key=clerk_public_key, algorithms=["RS256"])
        mail = res["email"]

        secret_auth_uri = "https://app.infisical.com/api/v1/auth/universal-auth/login"
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        auth_data = {"clientId": os.getenv("clientId"), "clientSecret": os.getenv("clientSecret")}

        # Get access token
        response = requests.post(url=secret_auth_uri, headers=headers, data=auth_data)
        response.raise_for_status()
        access_token = response.json()["accessToken"]

        auth_headers = {"Authorization": f"Bearer {access_token}"}

        # Update SSH key
        url = f"https://us.infisical.com/api/v3/secrets/raw/SSH_KEY_{mail}"
        payload = {
            "environment": "prod",
            "secretValue": ssh.key_file,
            "workspaceId": "113f5a41-dbc3-447d-8b3a-6fe8e9e6e99c",
        }

        headers = {
            "Authorization": auth_headers["Authorization"],
            "Content-Type": "application/json",
        }

        response = requests.request("POST", url, json=payload, headers=headers)
        return {"response": "SSH credentials updated successfully"}

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update SSH credentials: {str(e)}",
        )


@router.post("/updateServiceNow")
async def update_servicenow_credentials(
    snow: Snow_key, credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)]
):
    try:
        token = credentials.credentials
        res = jwt.decode(token, key=clerk_public_key, algorithms=["RS256"])
        mail = res["email"]

        secret_auth_uri = "https://app.infisical.com/api/v1/auth/universal-auth/login"
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        auth_data = {"clientId": os.getenv("clientId"), "clientSecret": os.getenv("clientSecret")}

        # Get access token
        response = requests.post(url=secret_auth_uri, headers=headers, data=auth_data)
        response.raise_for_status()
        access_token = response.json()["accessToken"]

        auth_headers = {"Authorization": f"Bearer {access_token}"}

        # Update ServiceNow credentials
        snow_dict = {
            f"SNOW_KEY_{mail}": snow.snow_key,
            f"SNOW_INSTANCE_{mail}": snow.snow_instance,
            f"SNOW_USER_{mail}": snow.snow_user,
            f"SNOW_PASSWORD_{mail}": snow.snow_password,
        }

        for key, value in snow_dict.items():
            url = f"https://us.infisical.com/api/v3/secrets/raw/{key}"
            payload = {
                "environment": "prod",
                "secretValue": value,
                "workspaceId": "113f5a41-dbc3-447d-8b3a-6fe8e9e6e99c",
            }

            headers = {
                "Authorization": auth_headers["Authorization"],
                "Content-Type": "application/json",
            }

            # Using PATCH to update existing secret
            response = requests.request("PATCH", url, json=payload, headers=headers)
            response.raise_for_status()

        return {"response": "ServiceNow credentials updated successfully"}

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update ServiceNow credentials: {str(e)}",
        )


@router.post("/prometheus/config")
async def add_or_update_prometheus_config(
    cfg: PrometheusConfig,
    user_data: dict = Depends(verify_token),
):
    """Store or update Prometheus datasource configuration for the authenticated user.

    Expected Supabase table (must be created separately):

        create table "PrometheusConfigs" (
            id uuid primary key default gen_random_uuid(),
            user_id uuid not null references "Users"(id) on delete cascade,
            name text,
            base_url text not null,
            auth_type text default 'none',
            bearer_token text,
            created_at timestamptz default now(),
            updated_at timestamptz default now()
        );
    """
    try:
        user_id = user_data["user_id"]
        now = datetime.utcnow().isoformat()

        existing = supabase.table("PrometheusConfigs").select("id").eq("user_id", user_id).execute()
        if existing.data:
            config_id = existing.data[0]["id"]
            response = (
                supabase.table("PrometheusConfigs")
                .update(
                    {
                        "name": cfg.name,
                        "base_url": cfg.base_url,
                        "auth_type": cfg.auth_type,
                        "bearer_token": cfg.bearer_token,
                        "updated_at": now,
                    }
                )
                .eq("id", config_id)
                .execute()
            )
        else:
            response = (
                supabase.table("PrometheusConfigs")
                .insert(
                    {
                        "user_id": user_id,
                        "name": cfg.name,
                        "base_url": cfg.base_url,
                        "auth_type": cfg.auth_type,
                        "bearer_token": cfg.bearer_token,
                        "created_at": now,
                        "updated_at": now,
                    }
                )
                .execute()
            )

        return {"response": response}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to store Prometheus configuration: {str(e)}",
        )


@router.get("/prometheus/config")
async def get_prometheus_config(user_data: dict = Depends(verify_token)):
    """Return Prometheus datasource configuration for the authenticated user (if any)."""
    try:
        user_id = user_data["user_id"]
        response = (
            supabase.table("PrometheusConfigs")
            .select("*")
            .eq("user_id", user_id)
            .limit(1)
            .execute()
        )
        if not response.data:
            return {"response": None}
        # Return only the first config for this user
        return {"response": response.data[0]}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch Prometheus configuration: {str(e)}",
        )


@router.post("/addSlackCredentials")
def addSlackCredentials(config: SlackConfig, user_data: dict = Depends(verify_token)):
    try:
        user_id = user_data.get("sub") or user_data.get("user_id")
        if not user_id:
            raise HTTPException(status_code=401, detail="User ID not found in token")

        # Use email if available for user-scoped secret key, else fallback to user_id
        user_email = user_data.get("email")
        # For now, let's trust the token has email or use user_id as identifier suffix
        identifier = user_email if user_email else user_id

        # Debug logging
        print(f"DEBUG addSlackCredentials: user_data keys={list(user_data.keys())}")
        print(
            f"DEBUG addSlackCredentials: user_email raw='{user_email}', identifier='{identifier}'"
        )
        print(
            f"DEBUG addSlackCredentials: slack_bot_token present={bool(config.slack_bot_token)}, slack_channel='{config.slack_channel}'"
        )

        # Store in Infisical
        secrets = {"SLACK_BOT_TOKEN": config.slack_bot_token, "SLACK_CHANNEL": config.slack_channel}

        try:
            set_many(identifier, secrets)
        except requests.exceptions.HTTPError as http_err:
            # Check if it's a 400 error related to the secret name
            if http_err.response.status_code == 400:
                # Use full email without sanitization
                print(
                    f"DEBUG addSlackCredentials: Got 400 error with identifier {identifier}, trying without sanitization..."
                )
                set_many(identifier, secrets)
            else:
                raise

        return {"message": "Slack credentials saved to Infisical"}
    except Exception as e:
        print(f"ERROR in addSlackCredentials: {str(e)}")
        import traceback

        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/getSlackCredentials/{mail}")
def getSlackCredentials(mail: str, user_data: dict = Depends(verify_token)):
    try:
        # Debug: Log what we're looking for
        print(f"DEBUG getSlackCredentials: mail={mail}")

        # Retrieve from Infisical using the mail param which should match what was used to save
        # Or verify against token email if strictly enforcing ownership

        # NOTE: existing frontend passes email in URL.
        secrets = get_many(mail, ("SLACK_BOT_TOKEN", "SLACK_CHANNEL"))

        print(f"DEBUG getSlackCredentials: secrets found = {secrets}")

        if not secrets.get("SLACK_BOT_TOKEN"):
            # Return empty or 404? Existing returned {} if not found
            print(f"DEBUG getSlackCredentials: No SLACK_BOT_TOKEN found for {mail}")
            return {}

        return {
            "response": {
                "slack_bot_token": secrets["SLACK_BOT_TOKEN"],
                "slack_channel": secrets.get("SLACK_CHANNEL"),
            }
        }
    except Exception as e:
        print(f"ERROR in getSlackCredentials: {str(e)}")
        import traceback

        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/addEmailCredentials")
def addEmailCredentials(config: EmailConfig, user_data: dict = Depends(verify_token)):
    try:
        # We need an identifier for Infisical. Prefer email.
        user_email = user_data.get("email")
        if not user_email:
            # Try to get from user_id or sub if email not in token (might need lookup)
            # For now assume frontend passes correct mail or token has it.
            # If we can't get email, we can't use email-scoped secrets easily without a mapping.
            # Let's rely on the user knowing their email or passing it.
            # Actually, let's use the user_id as fallback or fetch from DB if needed.
            pass

        # Simplified: Use the email from the config? No, config has sender_email.
        identifier = config.sender_email  # Use sender email as key suffix? Or user's login email?
        # Standardize on using the 'mail' param from GET often used, or token email.
        # Let's assume the user wants to store secrets associated with the sender_email they are configuring.
        identifier = config.sender_email

        secrets = {
            "SMTP_SERVER": config.smtp_server,
            "SMTP_PORT": str(config.smtp_port),
            "SENDER_EMAIL": config.sender_email,
            "SENDER_PASSWORD": config.sender_password,
        }
        set_many(identifier, secrets)

        return {"message": "Email credentials saved to Infisical"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/getEmailCredentials/{mail}")
def getEmailCredentials(mail: str, user_data: dict = Depends(verify_token)):
    try:
        secrets = get_many(mail, ("SMTP_SERVER", "SMTP_PORT", "SENDER_EMAIL", "SENDER_PASSWORD"))

        if not secrets.get("SENDER_EMAIL"):
            return {"response": {}}

        return {
            "response": {
                "smtp_server": secrets.get("SMTP_SERVER", "smtp.gmail.com"),
                "smtp_port": int(secrets.get("SMTP_PORT", 587)),
                "sender_email": secrets["SENDER_EMAIL"],
                "sender_password": secrets["SENDER_PASSWORD"],
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
