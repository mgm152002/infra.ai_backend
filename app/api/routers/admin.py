from fastapi import APIRouter, Depends, HTTPException, Body
from typing import List, Optional
from pydantic import BaseModel, EmailStr
from app.core.database import supabase
from app.core.security import verify_token, RoleChecker

# Only admins can access these routes
allow_admin = RoleChecker(["admin"])

router = APIRouter(dependencies=[Depends(verify_token), Depends(allow_admin)])

# --- Models ---
class UserCreate(BaseModel):
    email: EmailStr
    clerk_id: Optional[str] = None
    role: str = "viewer" # default role

class UserUpdate(BaseModel):
    role: Optional[str] = None

# --- User Management ---

@router.get("/users")
def get_users():
    # Fetch users and their roles
    # We might need to join with UserRoles and Roles
    # For simplicity, let's fetch users first, then their roles? 
    # Or use Supabase generic join if possible.
    
    # 1. Get all users
    users_resp = supabase.table("Users").select("*").execute()
    users = users_resp.data
    
    # 2. Get all user roles
    # This acts as a poor man's join if we don't have view set up
    user_roles_resp = supabase.table("UserRoles").select("user_id, Roles(name)").execute()
    
    # Map roles to users
    roles_map = {}
    if user_roles_resp.data:
        for item in user_roles_resp.data:
            uid = item['user_id']
            rname = item['Roles']['name'] if item.get('Roles') else None
            if rname:
                if uid not in roles_map: roles_map[uid] = []
                roles_map[uid].append(rname)
    
    # Merge
    result = []
    for u in users:
        u['roles'] = roles_map.get(u['id'], [])
        result.append(u)
        
    return result

@router.post("/users")
def create_user(user: UserCreate):
    # 1. Create User in Users table
    # Check if exists
    existing = supabase.table("Users").select("*").eq("email", user.email).execute()
    if existing.data:
        raise HTTPException(status_code=400, detail="User with this email already exists")
    
    new_user_payload = {"email": user.email}
    if user.clerk_id:
        new_user_payload["clerk_id"] = user.clerk_id
        
    user_resp = supabase.table("Users").insert(new_user_payload).execute()
    if not user_resp.data:
        raise HTTPException(status_code=500, detail="Failed to create user")
        
    new_user_id = user_resp.data[0]['id']
    
    # 2. Assign Role
    # Find role ID
    role_resp = supabase.table("Roles").select("id").eq("name", user.role).single().execute()
    if not role_resp.data:
        # Fallback to viewer or error?
        raise HTTPException(status_code=400, detail=f"Role '{user.role}' not found")
        
    role_id = role_resp.data['id']
    
    supabase.table("UserRoles").insert({
        "user_id": new_user_id,
        "role_id": role_id
    }).execute()
    
    return {"message": "User created successfully", "user": user_resp.data[0]}

@router.delete("/users/{id}")
def delete_user(id: int):
    # Cascade delete should handle UserRoles
    response = supabase.table("Users").delete().eq("id", id).execute()
    if not response.data:
         raise HTTPException(status_code=404, detail="User not found")
    return {"message": "User deleted successfully"}

# --- Role Management (Read Only for now) ---
@router.get("/roles")
def get_roles():
    response = supabase.table("Roles").select("*").execute()
    return response.data
