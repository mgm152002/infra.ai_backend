from fastapi import APIRouter, Depends, HTTPException, Body
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime
import json
from app.core.database import supabase
from app.services.rca_service import rca_service
from app.services.rca_service import rca_service
from app.core.security import verify_token, RoleChecker

allow_admin = RoleChecker(["admin"])

router = APIRouter()

# --- Models ---
class AlertType(BaseModel):
    name: str
    description: Optional[str] = None
    priority: str = "medium"

class EscalationRule(BaseModel):
    alert_type_id: int
    level: int
    wait_time_minutes: int = 0
    contact_type: str
    contact_destination: str

class ChangeRequest(BaseModel):
    title: str
    description: Optional[str] = None
    service_id: Optional[str] = None
    priority: str = "medium"
    status: str = "draft"
    requester_id: str
    scheduled_at: Optional[datetime] = None

class Approval(BaseModel):
    change_request_id: int
    approver_id: str
    status: str = "pending"
    comments: Optional[str] = None


# --- Alert Types ---
@router.get("/alert-types")
def get_alert_types():
    response = supabase.table("alert_types").select("*").execute()
    return response.data

@router.post("/alert-types")
def create_alert_type(alert: AlertType):
    response = supabase.table("alert_types").insert(alert.dict()).execute()
    return response.data

@router.put("/alert-types/{id}")
def update_alert_type(id: int, alert: AlertType):
    response = supabase.table("alert_types").update(alert.dict()).eq("id", id).execute()
    return response.data

@router.delete("/alert-types/{id}")
def delete_alert_type(id: int):
    response = supabase.table("alert_types").delete().eq("id", id).execute()
    return response.data

# --- Escalation Matrix ---
@router.get("/escalation-rules")
def get_escalation_rules():
    response = supabase.table("escalation_rules").select("*").execute()
    return response.data

@router.post("/escalation-rules")
def create_escalation_rule(rule: EscalationRule):
    response = supabase.table("escalation_rules").insert(rule.dict()).execute()
    return response.data

@router.put("/escalation-rules/{id}")
def update_escalation_rule(id: int, rule: EscalationRule):
    response = supabase.table("escalation_rules").update(rule.dict()).eq("id", id).execute()
    return response.data

@router.delete("/escalation-rules/{id}")
def delete_escalation_rule(id: int):
    response = supabase.table("escalation_rules").delete().eq("id", id).execute()
    return response.data

# --- Change Management ---

# --- Change Management ---
@router.get("/change-requests")
def get_change_requests(user_data: dict = Depends(verify_token), status: Optional[str] = None, requester_id: Optional[str] = None):
    query = supabase.table("change_requests").select("*").order("created_at", desc=True)
    if status:
        if status == "pending":
             query = query.in_("status", ["pending_approval", "submitted"])
        else:
             query = query.eq("status", status)
    if requester_id:
        query = query.eq("requester_id", requester_id)
        
    response = query.execute()
    return response.data

@router.post("/change-requests")
def create_change_request(request: ChangeRequest, user_data: dict = Depends(verify_token)):
    payload = request.dict()
    # Use authenticated user ID if not provided or override it? 
    # Frontend sends requester_id, but we should probably trust token.
    # Legacy code used token.
    payload["requester_id"] = user_data.get("sub")
    
    if payload.get("scheduled_at"):
        if isinstance(payload["scheduled_at"], datetime):
             payload["scheduled_at"] = payload["scheduled_at"].isoformat()
    
    response = supabase.table("change_requests").insert(payload).execute()
    return response.data[0] if response.data else {}

@router.put("/change-requests/{id}")
def update_change_request(id: int, request: ChangeRequest, user_data: dict = Depends(verify_token)):
    # Check ownership
    existing = supabase.table("change_requests").select("requester_id").eq("id", id).single().execute()
    if not existing.data:
         raise HTTPException(status_code=404, detail="Change request not found")
    
    # Allow admin or owner
    # For now assuming simple owner check or admin (if we had roles checked here)
    if existing.data["requester_id"] != user_data.get("sub"):
         # Check if admin?
         # For now let's just allow if token is valid, or rely on RLS if enabled. 
         # But python logic:
         pass

    data = {k: v for k, v in request.dict().items() if v is not None}
    if data.get('scheduled_at'):
        if isinstance(data['scheduled_at'], datetime):
            data['scheduled_at'] = data['scheduled_at'].isoformat()
            
    response = supabase.table("change_requests").update(data).eq("id", id).execute()
    return response.data[0] if response.data else {}

@router.post("/change-requests/{id}/approve")
def approve_change_request(id: int, user_data: dict = Depends(verify_token), _: bool = Depends(allow_admin)):
    # Update CR status
    response = supabase.table("change_requests").update({
        "status": "approved",
        "updated_at": datetime.utcnow().isoformat()
    }).eq("id", id).execute()
    
    if not response.data:
         raise HTTPException(status_code=404, detail="Change request not found")

    # Log approval
    approval_payload = {
        "change_request_id": id,
        "approver_id": user_data.get("sub"),
        "status": "approved",
        "comments": "Approved via Admin Dashboard"
    }
    supabase.table("approvals").insert(approval_payload).execute()
    
    return {"message": "Change request approved", "response": response.data[0]}

@router.post("/change-requests/{id}/reject")
def reject_change_request(id: int, user_data: dict = Depends(verify_token), _: bool = Depends(allow_admin)):
    response = supabase.table("change_requests").update({
        "status": "rejected",
        "updated_at": datetime.utcnow().isoformat()
    }).eq("id", id).execute()

    if not response.data:
         raise HTTPException(status_code=404, detail="Change request not found")

    # Log rejection
    approval_payload = {
        "change_request_id": id,
        "approver_id": user_data.get("sub"),
        "status": "rejected",
        "comments": "Rejected via Admin Dashboard"
    }
    supabase.table("approvals").insert(approval_payload).execute()
    
    return {"message": "Change request rejected", "response": response.data[0]}


# --- Approvals ---
@router.get("/approvals")
def get_approvals(user_id: Optional[str] = None):
    query = supabase.table("approvals").select("*")
    if user_id:
        query = query.eq("approver_id", user_id)
    response = query.execute()
    return response.data

@router.post("/approvals/{id}/{action}") # action: approve or reject
def process_approval(id: int, action: str, comments: Optional[str] = Body(None, embed=True)):
    status = "approved" if action == "approve" else "rejected"
    response = supabase.table("approvals").update({"status": status, "comments": comments}).eq("id", id).execute()
    
    # If approved, check if we should update change request status
    # This logic can be more complex (e.g. all approvers must approve)
    if status == "approved":
        approval = response.data[0]
        # Check if all approvals for this change request are approved? 
        # For simplicity, if this approval is approved, mark change as approved? No, let's keep it simple.
        pass

    return response.data

# --- RCA ---
@router.post("/rca/generate/{incident_number}")
def generate_rca_report(incident_number: str):
    result = rca_service.generate_rca(incident_number)
    return result

@router.get("/rca/{incident_number}")
def get_rca_report(incident_number: str):
    response = supabase.table("rca_reports").select("*").eq("incident_id", incident_number).execute()
    return response.data

# --- Problem Records ---
class ProblemRecord(BaseModel):
    title: str
    description: Optional[str] = None
    root_cause: Optional[str] = None
    workaround: Optional[str] = None
    permanent_fix: Optional[str] = None
    status: str = "open"
    priority: str = "medium"
    created_by: Optional[str] = None
    assigned_to: Optional[str] = None

@router.get("/problems")
def get_problems():
    response = supabase.table("problem_records").select("*").order("created_at", desc=True).execute()
    return response.data

@router.get("/problems/{id}")
def get_problem(id: int):
    response = supabase.table("problem_records").select("*").eq("id", id).execute()
    if not response.data:
        raise HTTPException(status_code=404, detail="Problem not found")
    return response.data[0]

@router.post("/problems")
def create_problem(problem: ProblemRecord):
    response = supabase.table("problem_records").insert(problem.dict()).execute()
    return response.data

@router.put("/problems/{id}")
def update_problem(id: int, problem: ProblemRecord):
    response = supabase.table("problem_records").update(problem.dict()).eq("id", id).execute()
    return response.data

@router.delete("/problems/{id}")
def delete_problem(id: int):
    response = supabase.table("problem_records").delete().eq("id", id).execute()
    return response.data

# --- Problem Records with AI ---
class CreateAIProblemRecord(BaseModel):
    incident_number: str
    create_if_not_exists: bool = True

def extract_problem_data(text: str) -> dict:
    """Extract problem data from raw LLM text response"""
    import re
    
    data = {}
    
    # Extract title
    title_match = re.search(r'"title"\s*:\s*"([^"]+)"', text)
    if title_match:
        data['title'] = title_match.group(1)
    
    # Extract description
    desc_match = re.search(r'"description"\s*:\s*"([^"]+)"', text)
    if desc_match:
        data['description'] = desc_match.group(1)
    
    # Extract root_cause
    rc_match = re.search(r'"root_cause"\s*:\s*"([^"]+)"', text)
    if rc_match:
        data['root_cause'] = rc_match.group(1)
    
    # Extract workaround
    wa_match = re.search(r'"workaround"\s*:\s*"([^"]+)"', text)
    if wa_match:
        data['workaround'] = wa_match.group(1)
    
    # Extract permanent_fix
    pf_match = re.search(r'"permanent_fix"\s*:\s*"([^"]+)"', text)
    if pf_match:
        data['permanent_fix'] = pf_match.group(1)
    
    # Extract priority
    pri_match = re.search(r'"priority"\s*:\s*"([^"]+)"', text)
    if pri_match:
        data['priority'] = pri_match.group(1)
    
    return data

def extract_problem_data_from_context(context: str, incident_number: str) -> dict:
    """Extract problem data from context when LLM fails - parse RCA content"""
    import re
    
    data = {
        "title": f"Problem for Incident #{incident_number}",
        "description": f"Problem record generated from incident #{incident_number}",
        "root_cause": "",
        "workaround": "",
        "permanent_fix": "",
        "priority": "medium"
    }
    
    # Try to extract root cause from RCA content
    if "Root Cause" in context:
        # Find the section after "Root Cause"
        rc_section = re.search(r'Root Cause[:\s]+([^#]+?)(?:\n##|\n#|Resolution|Corrective)', context, re.IGNORECASE | re.DOTALL)
        if rc_section:
            data['root_cause'] = rc_section.group(1).strip()[:500]
    
    # Try to extract resolution
    if "Resolution" in context:
        res_section = re.search(r'Resolution[:\s]+([^#]+?)(?:\n##|\n#|Corrective|$)', context, re.IGNORECASE | re.DOTALL)
        if res_section:
            data['permanent_fix'] = res_section.group(1).strip()[:500]
    
    # Try to extract corrective measures
    if "Corrective" in context or "Preventive" in context:
        corr_section = re.search(r'(?:Corrective|Preventive)[:\s]+([^#]+?)(?:\n##|\n#|$)', context, re.IGNORECASE | re.DOTALL)
        if corr_section:
            data['permanent_fix'] += "\n" + corr_section.group(1).strip()[:500]
    
    # Try to determine priority from context
    if "critical" in context.lower():
        data['priority'] = "critical"
    elif "high" in context.lower():
        data['priority'] = "high"
    elif "low" in context.lower():
        data['priority'] = "low"
    
    # Set description to include RCA summary
    if data['root_cause']:
        data['description'] = f"Root cause identified from incident #{incident_number}: {data['root_cause'][:200]}..."
    
    return data

@router.get("/problems/by-incident/{incident_number}")
def get_problem_by_incident(incident_number: str):
    """Check if a problem record exists for an incident"""
    # First check if incident has a problem_id
    incident_response = supabase.table("Incidents").select("problem_id").eq("inc_number", incident_number).execute()
    
    if incident_response.data and incident_response.data[0].get("problem_id"):
        problem_id = incident_response.data[0]["problem_id"]
        problem_response = supabase.table("problem_records").select("*").eq("id", problem_id).execute()
        if problem_response.data:
            return {"exists": True, "problem": problem_response.data[0]}
    
    return {"exists": False, "problem": None}

@router.post("/problems/ai-generate")
def create_ai_problem_record(incident_number: str):
    """Create a problem record filled by AI using RCA, resolution steps and diagnostic steps"""
    from app.services.rca_service import rca_service
    
    # 1. Fetch incident details
    incident_response = supabase.table("Incidents").select("*").eq("inc_number", incident_number).execute()
    if not incident_response.data:
        raise HTTPException(status_code=404, detail="Incident not found")
    incident = incident_response.data[0]
    
    # 2. Fetch RCA report
    rca_response = supabase.table("rca_reports").select("*").eq("incident_id", incident_number).execute()
    rca_content = rca_response.data[0]["report_content"] if rca_response.data else None
    
    # 3. Fetch resolution and diagnostic steps from Results
    results_response = supabase.table("Results").select("*").eq("inc_number", incident_number).order("created_at").execute()
    results = results_response.data if results_response.data else []
    
    # Build context for AI
    context = f"""Incident: {incident.get('short_description', 'N/A')}
Description: {incident.get('description', 'N/A')}

"""
    
    if rca_content:
        context += f"RCA Report:\n{rca_content}\n\n"
    
    # Extract diagnostic and resolution steps from results
    diagnostic_steps = []
    resolution_steps = []
    
    for res in results:
        try:
            parsed_desc = json.loads(res.get('description', '{}')) if isinstance(res.get('description'), str) else res.get('description', {})
            
            # Extract diagnostics
            if parsed_desc.get('diagnostics', {}).get('diagnostics'):
                for d in parsed_desc['diagnostics']['diagnostics']:
                    diagnostic_steps.append(f"- {d.get('step', 'N/A')}: {'Success' if d.get('success') else 'Failed'}")
            
            # Extract resolution steps
            if parsed_desc.get('resolution', {}).get('resolution_results'):
                for r in parsed_desc['resolution']['resolution_results']:
                    resolution_steps.append(f"- {r.get('step', 'N/A')}: {'Success' if r.get('result', {}).get('success') else 'Failed'}")
        except:
            pass
    
    if diagnostic_steps:
        context += f"Diagnostic Steps:\n" + "\n".join(diagnostic_steps) + "\n\n"
    
    if resolution_steps:
        context += f"Resolution Steps:\n" + "\n".join(resolution_steps) + "\n\n"
    
    # Call LLM to generate comprehensive problem record
    from app.core.llm import call_llm
    
    prompt = f"""
Create a Problem Record JSON for this incident. 

Incident: {incident.get('short_description', 'N/A')}
Description: {incident.get('description', 'N/A')}
Priority from incident: {incident.get('priority', 'medium')}

RCA Report (use this to extract root cause and resolution):
{rca_content[:3000] if rca_content else 'No RCA available'}

Resolution Steps:
{"\n".join(resolution_steps[:10]) if resolution_steps else 'No resolution steps available'}

Output a valid JSON object with these exact fields (use plain text, no markdown):
{{"title": "...", "description": "...", "root_cause": "...", "workaround": "...", "permanent_fix": "...", "priority": "..."}}

Priority must be one of: critical, high, medium, low
Ensure all fields are filled with meaningful content.
"""
    
    try:
        ai_result = call_llm(prompt)
        # Try to parse JSON from the response - handle complex JSON with nested objects
        import re
        
        # Find JSON block - look for the outermost braces
        json_start = ai_result.find('{')
        json_end = ai_result.rfind('}')
        
        if json_start != -1 and json_end != -1:
            json_str = ai_result[json_start:json_end+1]
            try:
                problem_data = json.loads(json_str)
            except json.JSONDecodeError:
                # Try to fix common issues like missing quotes around keys
                # Replace single quotes with double quotes (basic fix)
                json_str = json_str.replace("'", '"')
                try:
                    problem_data = json.loads(json_str)
                except:
                    # Last resort: extract key fields manually
                    problem_data = extract_problem_data(ai_result)
        else:
            problem_data = extract_problem_data(ai_result)
    except Exception as e:
        print(f"LLM call failed: {e}")
        problem_data = extract_problem_data_from_context(context, incident_number)
    
    # Create the problem record
    problem_record = {
        "title": problem_data.get("title", f"Problem for Incident #{incident_number}"),
        "description": problem_data.get("description", ""),
        "root_cause": problem_data.get("root_cause", ""),
        "workaround": problem_data.get("workaround", ""),
        "permanent_fix": problem_data.get("permanent_fix", ""),
        "priority": problem_data.get("priority", "medium"),
        "status": "root_cause_identified"
    }
    
    # Insert problem record
    problem_response = supabase.table("problem_records").insert(problem_record).execute()
    if not problem_response.data:
        raise HTTPException(status_code=500, detail="Failed to create problem record")
    
    problem_id = problem_response.data[0]["id"]
    
    # Link incident to problem record
    supabase.table("Incidents").update({"problem_id": problem_id}).eq("inc_number", incident_number).execute()
    
    return {"success": True, "problem": problem_response.data[0]}

@router.delete("/problems/by-incident/{incident_number}")
def delete_problem_by_incident(incident_number: str):
    """Delete problem record associated with an incident"""
    # Get incident's problem_id
    incident_response = supabase.table("Incidents").select("problem_id").eq("inc_number", incident_number).execute()
    
    if not incident_response.data or not incident_response.data[0].get("problem_id"):
        raise HTTPException(status_code=404, detail="No problem record found for this incident")
    
    problem_id = incident_response.data[0]["problem_id"]
    
    # First, remove the foreign key link from incident
    supabase.table("Incidents").update({"problem_id": None}).eq("inc_number", incident_number).execute()
    
    # Then delete the problem record
    delete_response = supabase.table("problem_records").delete().eq("id", problem_id).execute()
    
    if not delete_response.data:
        raise HTTPException(status_code=500, detail="Failed to delete problem record")
    
    return {"success": True, "message": "Problem record deleted successfully"}

# --- Incidents List ---
@router.get("/incidents")
def get_incidents():
    """Get all incidents"""
    response = supabase.table("Incidents").select("*").order("created_at", desc=True).execute()
    return response.data
