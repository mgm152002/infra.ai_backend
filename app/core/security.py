import os
import time
import threading
import asyncio
from fastapi import HTTPException, status, Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from typing import Annotated, Dict, Any, List
import jwt
from jwt import PyJWTError
from app.core.config import settings
from app.core.logger import logger
from app.core.database import supabase

security_scheme = HTTPBearer()

# supabase client is imported from app.core.database

_AUTH_USER_CACHE_TTL_S = float(os.getenv("AUTH_USER_CACHE_TTL_S", "300"))
_AUTH_USER_CACHE_STALE_GRACE_S = float(os.getenv("AUTH_USER_CACHE_STALE_GRACE_S", "3600"))
_AUTH_DB_LOOKUP_TIMEOUT_S = float(os.getenv("AUTH_DB_LOOKUP_TIMEOUT_S", "120"))
_AUTH_DB_TOTAL_BUDGET_S = float(os.getenv("AUTH_DB_TOTAL_BUDGET_S", "180"))
_AUTH_LOOKUP_TIMEOUT_BACKOFF_S = float(os.getenv("AUTH_LOOKUP_TIMEOUT_BACKOFF_S", "60"))
_AUTH_FAIL_OPEN_ON_TIMEOUT = (
    os.getenv("AUTH_FAIL_OPEN_ON_TIMEOUT", "true").strip().lower() in {"1", "true", "yes", "on"}
)
_AUTH_USER_CACHE: Dict[str, Dict[str, Any]] = {}
_AUTH_USER_CACHE_LOCK = threading.Lock()
_AUTH_LOOKUP_BACKOFF_UNTIL_TS = 0.0


def _cache_key(principal: str) -> str:
    return (principal or "").strip().lower()


def _get_cached_user_id(principal: str, *, allow_stale: bool = False) -> Any:
    key = _cache_key(principal)
    if not key:
        return None
    now = time.time()
    with _AUTH_USER_CACHE_LOCK:
        item = _AUTH_USER_CACHE.get(key)
        if not item:
            return None
        age = now - float(item.get("ts", 0))
        if age <= _AUTH_USER_CACHE_TTL_S:
            return item.get("user_id")
        if allow_stale and age <= (_AUTH_USER_CACHE_TTL_S + _AUTH_USER_CACHE_STALE_GRACE_S):
            return item.get("user_id")
        return None


def _set_cached_user_id(principal: str, user_id: Any) -> None:
    key = _cache_key(principal)
    if not key or user_id is None:
        return
    with _AUTH_USER_CACHE_LOCK:
        _AUTH_USER_CACHE[key] = {"user_id": user_id, "ts": time.time()}


def _is_lookup_backoff_active() -> bool:
    if _AUTH_LOOKUP_TIMEOUT_BACKOFF_S <= 0:
        return False
    with _AUTH_USER_CACHE_LOCK:
        return time.time() < _AUTH_LOOKUP_BACKOFF_UNTIL_TS


def _note_lookup_timeout() -> None:
    if _AUTH_LOOKUP_TIMEOUT_BACKOFF_S <= 0:
        return
    global _AUTH_LOOKUP_BACKOFF_UNTIL_TS
    with _AUTH_USER_CACHE_LOCK:
        _AUTH_LOOKUP_BACKOFF_UNTIL_TS = max(
            _AUTH_LOOKUP_BACKOFF_UNTIL_TS,
            time.time() + _AUTH_LOOKUP_TIMEOUT_BACKOFF_S,
        )


def _auth_response(
    *,
    email: str,
    token: str,
    clerk_id: str | None,
    user_id: Any,
    auth_degraded: bool = False,
) -> Dict[str, Any]:
    return {
        "email": email,
        "user_id": user_id,
        "token": token,
        "clerk_id": clerk_id,
        "auth_degraded": auth_degraded,
    }


async def _run_supabase_lookup_with_timeout(operation, timeout_s: float, operation_name: str):
    """Run sync Supabase lookup on threadpool with a bounded timeout."""
    try:
        return await asyncio.wait_for(asyncio.to_thread(operation), timeout=timeout_s)
    except asyncio.TimeoutError as e:
        msg = f"{operation_name} timed out after {timeout_s:.1f}s"
        logger.error(msg)
        raise TimeoutError(msg) from e


async def verify_token(credentials: Annotated[HTTPAuthorizationCredentials, Depends(security_scheme)]) -> Dict[str, Any]:
    """Validate JWT from Authorization header and return basic user data.
    
    Expects Clerk JWT with 'email' claim (configured via Clerk JWT Templates).
    """
    try:
        token = credentials.credentials
        logger.debug(f"Received token (first 50 chars): {token[:50] if token else 'None'}...")
        
        # Decode JWT using Clerk public key
        payload = jwt.decode(token, key=settings.CLERK_PUBLIC_KEY, algorithms=['RS256'])
        logger.debug(f"Decoded payload keys: {list(payload.keys())}")
        clerk_id = payload.get("sub")
        
        # Get email from JWT (must be configured in Clerk JWT Templates)
        email = payload.get("email")
        if not email:
            logger.warning(f"Email not found in JWT. Available claims: {list(payload.keys())}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Email not found in token. Please configure Clerk JWT template to include email.",
            )

        # Fast path: in-memory cache by clerk_id/email to avoid DB hit on every poll.
        cached_user_id = _get_cached_user_id(clerk_id or "") or _get_cached_user_id(email)
        if cached_user_id is not None:
            return _auth_response(email=email, user_id=cached_user_id, token=token, clerk_id=clerk_id)

        # Circuit-break repeated timeouts: avoid hammering the DB when auth lookups are already timing out.
        if _is_lookup_backoff_active():
            stale_user_id = _get_cached_user_id(clerk_id or "", allow_stale=True) or _get_cached_user_id(email, allow_stale=True)
            if stale_user_id is not None:
                logger.warning(f"Using stale auth cache for {email} while auth lookup backoff is active")
                return _auth_response(email=email, user_id=stale_user_id, token=token, clerk_id=clerk_id)
            if _AUTH_FAIL_OPEN_ON_TIMEOUT:
                logger.warning(f"Auth DB lookup backoff active; proceeding without user_id for {email}")
                return _auth_response(email=email, user_id=None, token=token, clerk_id=clerk_id, auth_degraded=True)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database lookup timed out while validating token",
            )
        
        user_response = None
        timed_out = False
        skip_email_lookup = False
        start_ts = time.monotonic()

        # Preferred lookup: clerk_id (indexed), then fallback to email.
        if clerk_id:
            try:
                remaining = max(0.0, _AUTH_DB_TOTAL_BUDGET_S - (time.monotonic() - start_ts))
                lookup_timeout = min(_AUTH_DB_LOOKUP_TIMEOUT_S, remaining)
                if lookup_timeout <= 0:
                    raise TimeoutError("auth DB budget exhausted")
                user_response = await _run_supabase_lookup_with_timeout(
                    lambda: supabase.table("Users").select("id").eq("clerk_id", clerk_id).limit(1).execute(),
                    timeout_s=lookup_timeout,
                    operation_name="verify_token_user_lookup_by_clerk_id",
                )
            except TimeoutError:
                timed_out = True
                skip_email_lookup = True
                _note_lookup_timeout()
                logger.warning(
                    "verify_token_user_lookup_by_clerk_id timed out; skipping email fallback for this request"
                )
                stale_user_id = _get_cached_user_id(clerk_id or "", allow_stale=True) or _get_cached_user_id(email or "", allow_stale=True)
                if stale_user_id is not None:
                    logger.warning(f"Using stale auth cache for {email} after clerk_id lookup timeout")
                    return _auth_response(email=email, user_id=stale_user_id, token=token, clerk_id=clerk_id)

        if (not user_response or not user_response.data) and not skip_email_lookup:
            try:
                remaining = max(0.0, _AUTH_DB_TOTAL_BUDGET_S - (time.monotonic() - start_ts))
                lookup_timeout = min(_AUTH_DB_LOOKUP_TIMEOUT_S, remaining)
                if lookup_timeout <= 0:
                    raise TimeoutError("auth DB budget exhausted")
                user_response = await _run_supabase_lookup_with_timeout(
                    lambda: supabase.table("Users").select("id").eq("email", email).limit(1).execute(),
                    timeout_s=lookup_timeout,
                    operation_name="verify_token_user_lookup",
                )
            except TimeoutError:
                timed_out = True
                _note_lookup_timeout()
                logger.warning("verify_token_user_lookup timed out")

        if not user_response or not user_response.data:
            # Degraded mode: use recently cached user mapping if available.
            stale_user_id = _get_cached_user_id(clerk_id or "", allow_stale=True) or _get_cached_user_id(email or "", allow_stale=True)
            if stale_user_id is not None:
                logger.warning(f"Using stale auth cache for {email} due to user lookup timeout")
                return _auth_response(email=email, user_id=stale_user_id, token=token, clerk_id=clerk_id)
            if timed_out:
                if _AUTH_FAIL_OPEN_ON_TIMEOUT:
                    logger.warning(f"Auth DB lookup timed out; proceeding without user_id for {email}")
                    return _auth_response(email=email, user_id=None, token=token, clerk_id=clerk_id, auth_degraded=True)
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Database lookup timed out while validating token",
                )
            logger.warning(f"User not found in DB: {email}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )

        user_id = user_response.data[0]["id"]
        _set_cached_user_id(email, user_id)
        if clerk_id:
            _set_cached_user_id(clerk_id, user_id)
        logger.debug(f"Token validated successfully for user: {email}")
        return _auth_response(email=email, user_id=user_id, token=token, clerk_id=clerk_id)
        
    except HTTPException:
        raise
    except PyJWTError as e:
        logger.error(f"JWT Error: {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials - invalid token",
        )

async def get_current_user(user_data: Dict[str, Any] = Depends(verify_token)) -> Dict[str, Any]:
    return user_data

def get_user_roles(user_id: Any) -> List[str]:
    """Fetch roles for a user from the database."""
    if user_id is None:
        return []
    try:
        # Join UserRoles with Roles table
        # Supabase syntax for joins: "*, Roles(*)" or similar depending on setup
        # But straightforward manual join might be safer if FKs are set up:
        # .select("Roles(name)") from UserRoles where user_id=...
        response = supabase.table("UserRoles").select("Roles(name)").eq("user_id", user_id).execute()
        
        roles = []
        if response.data:
            for item in response.data:
                role_data = item.get("Roles")
                if role_data:
                    roles.append(role_data.get("name"))
        return roles
    except Exception as e:
        logger.error(f"Error fetching roles for user {user_id}: {str(e)}")
        return []

class RoleChecker:
    def __init__(self, allowed_roles: List[str]):
        self.allowed_roles = allowed_roles

    def __call__(self, user: Dict[str, Any] = Depends(get_current_user)):
        user_roles = get_user_roles(user['user_id'])
        # If admin is in user_roles, always allow (optional policy)
        if 'admin' in user_roles:
            return user
            
        # Check intersection
        if not any(role in self.allowed_roles for role in user_roles):
             logger.warning(f"Access denied for user {user.get('email')}. Required: {self.allowed_roles}, Has: {user_roles}")
             raise HTTPException(status_code=403, detail="Not enough permissions")
        return user

def has_permission(resource: str, action: str):
    """
    Dependency to check if user has specific permission on a resource.
    """
    def permission_checker(user: Dict[str, Any] = Depends(get_current_user)):
        user_id = user['user_id']
        if user_id is None:
            logger.warning(
                f"Permission denied: missing user_id while checking {resource}:{action} for {user.get('email')}"
            )
            raise HTTPException(status_code=403, detail="Permission denied")
        try:
            # Get all roles for user
            role_ids_resp = supabase.table("UserRoles").select("role_id").eq("user_id", user_id).execute()
            if not role_ids_resp.data:
                raise HTTPException(status_code=403, detail="User has no roles")
            
            role_ids = [r['role_id'] for r in role_ids_resp.data]
            
            # Check RolePermissions for these roles matching resource & action
            # We need to join RolePermissions -> Permissions
            # This complex query might be better as a Postgres Function (RPC), 
            # but for now we try a client-side filter or simpler query.
            
            # 1. Get Permission ID for resource+action
            perm_resp = supabase.table("Permissions").select("id").eq("resource", resource).eq("action", action).execute()
            if not perm_resp.data:
                # Permission doesn't exist -> deny (safe default)
                logger.warning(f"Permission check failed: Permission {resource}:{action} not defined.")
                raise HTTPException(status_code=403, detail="Permission denied (invalid permission)")
            
            perm_id = perm_resp.data[0]['id']
            
            # 2. Check if any of user's roles has this permission
            rp_resp = supabase.table("RolePermissions").select("*") \
                .in_("role_id", role_ids) \
                .eq("permission_id", perm_id) \
                .execute()
                
            if rp_resp.data and len(rp_resp.data) > 0:
                return True
                
            logger.warning(f"Access denied for user {user_id}. Missing permission: {resource}:{action}")
            raise HTTPException(status_code=403, detail="Permission denied")
            
        except HTTPException as he:
            raise he
        except Exception as e:
            logger.exception(f"Permission check error: {str(e)}")
            raise HTTPException(status_code=500, detail="Internal server error checking permissions")
            
    return permission_checker
