""""CMDB inventory and service-management API routes."""

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status

from app.core.database import supabase
from app.core.security import verify_token
from app.schemas.models import CMDBItem, CMDBItemUpdate, Service, ServiceUpdate

router = APIRouter()

@router.get("/cmdb", response_model=dict)
async def get_all_cmdb_items(user_data: dict = Depends(verify_token)):
    try:
        response = supabase.table("CMDB").select("*, Users(*)").eq("user_id", user_data["user_id"]).execute()
        return {"response": response}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(e)}"
        )

# Get CMDB items grouped by service
@router.get("/cmdb/by-service", response_model=dict)
async def get_cmdb_by_service(user_data: dict = Depends(verify_token)):
    """Get CMDB items grouped by service"""
    try:
        # Get all services
        services_response = supabase.table("services").select("*").order("name").execute()
        services = services_response.data or []

        # Get all CMDB items for this user
        cmdb_response = supabase.table("CMDB").select("*, Users(*)").eq("user_id", user_data["user_id"]).execute()
        cmdb_items = cmdb_response.data or []

        # Group CMDB items by service_id
        unassigned = []
        grouped = {}

        for item in cmdb_items:
            service_id = item.get("service_id")
            if service_id:
                if service_id not in grouped:
                    grouped[service_id] = []
                grouped[service_id].append(item)
            else:
                unassigned.append(item)

        # Build response with service info and hosts
        result = []
        for service in services:
            service_id = service["id"]
            result.append({
                "service": service,
                "hosts": grouped.get(service_id, []),
                "host_count": len(grouped.get(service_id, []))
            })

        # Add unassigned hosts
        result.append({
            "service": {"id": None, "name": "Unassigned", "description": "Hosts not assigned to any service"},
            "hosts": unassigned,
            "host_count": len(unassigned)
        })

        return {"response": result}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(e)}"
        )

# Get CMDB item by tag_id (only if it belongs to the authenticated user)
@router.get("/cmdb/{tag_id}", response_model=dict)
async def get_cmdb_item(tag_id: str, user_data: dict = Depends(verify_token)):
    try:
        response = supabase.table("CMDB").select("*, Users(*)").eq("tag_id", tag_id).eq("user_id", user_data["user_id"]).execute()
        if not response.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"CMDB item with tag_id {tag_id} not found or does not belong to you"
            )
        return {"response": response}
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(e)}"
        )

# Create new CMDB item with user_id
@router.post("/cmdb", response_model=dict, status_code=status.HTTP_201_CREATED)
async def create_cmdb_item(item: CMDBItem, user_data: dict = Depends(verify_token)):
    try:
        # Check if tag_id already exists for this user
        existing = supabase.table("CMDB").select("tag_id").eq("tag_id", item.tag_id).eq("user_id", user_data["user_id"]).execute()
        if existing.data:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"CMDB item with tag_id {item.tag_id} already exists for this user"
            )

        # Validate service_id if provided
        if item.service_id:
            service_check = supabase.table("services").select("id").eq("id", item.service_id).execute()
            if not service_check.data:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Service with id {item.service_id} does not exist"
                )

        # Create new item with user_id
        response = supabase.table("CMDB").insert({
            "tag_id": item.tag_id,
            "ip": str(item.ip),
            "addr": item.addr,
            "type": item.type,
            "os": item.os,
            "description": item.description,
            "sys_id": item.sys_id,
            "source": item.source,
            "raw_data": item.raw_data,
            "user_id": user_data["user_id"],  # Add user_id from token
            "service_id": item.service_id,  # Service reference
            "fqdn": item.fqdn,  # FQDN
            "created_at": datetime.utcnow().isoformat()
        }).execute()

        return {"response": response}
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(e)}"
        )

# Update CMDB item (only if it belongs to the authenticated user)
@router.put("/cmdb/{tag_id}", response_model=dict)
async def update_cmdb_item(
    tag_id: str,
    item: CMDBItemUpdate,
    user_data: dict = Depends(verify_token)
):
    try:
        # Check if item exists and belongs to this user
        existing = supabase.table("CMDB").select("*").eq("tag_id", tag_id).eq("user_id", user_data["user_id"]).execute()
        if not existing.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"CMDB item with tag_id {tag_id} not found or does not belong to you"
            )

        # Build update dictionary with only provided fields
        update_data = {}
        if item.tag_id is not None:
            update_data["tag_id"] = item.tag_id
        if item.ip is not None:
            update_data["ip"] = str(item.ip)
        if item.addr is not None:
            update_data["addr"] = item.addr
        if item.type is not None:
            update_data["type"] = item.type
        if item.description is not None:
            update_data["description"] = item.description
        if item.os is not None:
            update_data["os"] = item.os
        if item.service_id is not None:
            # Validate service_id if provided
            if item.service_id:
                service_check = supabase.table("services").select("id").eq("id", item.service_id).execute()
                if not service_check.data:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Service with id {item.service_id} does not exist"
                    )
            update_data["service_id"] = item.service_id
        if item.fqdn is not None:
            update_data["fqdn"] = item.fqdn
        update_data["updated_at"] = datetime.utcnow().isoformat()

        # Update item (user_id filter ensures user can only update their own items)
        response = supabase.table("CMDB").update(update_data).eq("tag_id", tag_id).eq("user_id", user_data["user_id"]).execute()

        return {"response": response}
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(e)}"
        )

# Delete CMDB item (only if it belongs to the authenticated user)
@router.delete("/cmdb/{tag_id}", response_model=dict)
async def delete_cmdb_item(tag_id: str, user_data: dict = Depends(verify_token)):
    try:
        # Check if item exists and belongs to this user
        existing = supabase.table("CMDB").select("*").eq("tag_id", tag_id).eq("user_id", user_data["user_id"]).execute()
        if not existing.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"CMDB item with tag_id {tag_id} not found or does not belong to you"
            )

        # Delete item (user_id filter ensures user can only delete their own items)
        response = supabase.table("CMDB").delete().eq("tag_id", tag_id).eq("user_id", user_data["user_id"]).execute()

        return {"response": response}
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(e)}"
        )

# Search CMDB items (only returns items that belong to the authenticated user)
@router.get("/cmdb/search/{query}", response_model=dict)
async def search_cmdb_items(query: str, user_data: dict = Depends(verify_token)):
    try:
        # Using ILIKE for case-insensitive search across multiple columns
        # And filtering by user_id for security
        response = supabase.table("CMDB").select("*, Users(*)").eq("user_id", user_data["user_id"]).or_(
            f"tag_id.ilike.%{query}%,ip.ilike.%{query}%,addr.ilike.%{query}%,type.ilike.%{query}%,description.ilike.%{query}%"
        ).execute()

        return {"response": response}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(e)}"
        )

# --- Service Management Routes (Global/Shared CMDB) ---

@router.get("/services", response_model=dict)
async def get_all_services(user_data: dict = Depends(verify_token)):
    """Get all services (global/shared, not user-specific)"""
    try:
        response = supabase.table("services").select("*").order("name").execute()
        return {"response": response}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(e)}"
        )

@router.get("/services/{service_id}", response_model=dict)
async def get_service(service_id: str, user_data: dict = Depends(verify_token)):
    """Get a specific service by ID"""
    try:
        response = supabase.table("services").select("*").eq("id", service_id).execute()
        if not response.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Service with id {service_id} not found"
            )
        return {"response": response}
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(e)}"
        )

@router.post("/services", response_model=dict, status_code=status.HTTP_201_CREATED)
async def create_service(service: Service, user_data: dict = Depends(verify_token)):
    """Create a new service (global/shared)"""
    try:
        # Check if service name already exists
        existing = supabase.table("services").select("id").eq("name", service.name).execute()
        if existing.data:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Service with name '{service.name}' already exists"
            )

        response = supabase.table("services").insert({
            "name": service.name,
            "description": service.description,
            "service_type": service.service_type,
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat()
        }).execute()

        return {"response": response}
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(e)}"
        )

@router.put("/services/{service_id}", response_model=dict)
async def update_service(service_id: str, service: ServiceUpdate, user_data: dict = Depends(verify_token)):
    """Update a service"""
    try:
        # Check if service exists
        existing = supabase.table("services").select("*").eq("id", service_id).execute()
        if not existing.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Service with id {service_id} not found"
            )

        # Build update dictionary with only provided fields
        update_data = {}
        if service.name is not None:
            # Check if new name conflicts with another service
            conflict = supabase.table("services").select("id").eq("name", service.name).neq("id", service_id).execute()
            if conflict.data:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"Service with name '{service.name}' already exists"
                )
            update_data["name"] = service.name
        if service.description is not None:
            update_data["description"] = service.description
        if service.service_type is not None:
            update_data["service_type"] = service.service_type

        update_data["updated_at"] = datetime.utcnow().isoformat()

        response = supabase.table("services").update(update_data).eq("id", service_id).execute()

        return {"response": response}
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(e)}"
        )

@router.delete("/services/{service_id}", response_model=dict)
async def delete_service(service_id: str, user_data: dict = Depends(verify_token)):
    """Delete a service"""
    try:
        # Check if service exists
        existing = supabase.table("services").select("*").eq("id", service_id).execute()
        if not existing.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Service with id {service_id} not found"
            )

        # Check if there are hosts assigned to this service
        hosts_response = supabase.table("CMDB").select("tag_id").eq("service_id", service_id).execute()
        if hosts_response.data:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Cannot delete service. There are {len(hosts_response.data)} hosts assigned to this service. Please reassign them first."
            )

        response = supabase.table("services").delete().eq("id", service_id).execute()

        return {"response": response}
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(e)}"
        )

@router.get("/services/{service_id}/hosts", response_model=dict)
async def get_service_hosts(service_id: str, user_data: dict = Depends(verify_token)):
    """Get all hosts belonging to a specific service"""
    try:
        # First verify service exists
        service_response = supabase.table("services").select("*").eq("id", service_id).execute()
        if not service_response.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Service with id {service_id} not found"
            )

        # Get hosts for this service
        response = supabase.table("CMDB").select("*, Users(*)").eq("service_id", service_id).execute()

        return {
            "response": response,
            "service": service_response.data[0]
        }
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(e)}"
        )
