from typing import Union, Optional, List, Dict, Any
from pydantic import BaseModel
from pydantic.networks import IPvAnyAddress
from datetime import datetime

class ssh(BaseModel):
    key_file: str

class Service(BaseModel):
    """Service model for organizing hosts"""
    id: Optional[str] = None
    name: str
    description: Optional[str] = None
    service_type: Optional[str] = None  # web, database, api, cache, storage, etc.
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

class ServiceUpdate(BaseModel):
    """Service update model"""
    name: Optional[str] = None
    description: Optional[str] = None
    service_type: Optional[str] = None

class CMDBItem(BaseModel):
    tag_id: str
    ip: IPvAnyAddress
    addr: str
    os: str
    type: str
    description: str
    sys_id: Optional[str] = None
    source: Optional[str] = "manual"
    last_sync: Optional[datetime] = None
    raw_data: Optional[Dict[str, Any]] = None
    service_id: Optional[str] = None  # Link to service
    fqdn: Optional[str] = None  # Fully Qualified Domain Name

class CMDBItemUpdate(BaseModel):
    tag_id: Optional[str] = None
    ip: Optional[IPvAnyAddress] = None
    addr: Optional[str] = None
    os: Optional[str] = None
    type: Optional[str] = None
    description: Optional[str] = None
    service_id: Optional[str] = None
    fqdn: Optional[str] = None

class Snow_key(BaseModel):
    snow_key: str
    snow_instance: str
    snow_user: str
    snow_password: str

class PrometheusConfig(BaseModel):
    name: Optional[str] = None
    base_url: str
    auth_type: Optional[str] = "none"  # 'none' or 'bearer'
    bearer_token: Optional[str] = None

class DatadogConfig(BaseModel):
    api_key: str
    app_key: str
    site: Optional[str] = "datadoghq.com"

class GitHubIntegrationConfig(BaseModel):
    base_url: Optional[str] = None
    token: Optional[str] = None
    default_owner: Optional[str] = None
    default_repo: Optional[str] = None

class JiraIntegrationConfig(BaseModel):
    base_url: str
    email: Optional[str] = None
    api_token: str

class ConfluenceIntegrationConfig(BaseModel):
    base_url: str
    email: Optional[str] = None
    api_token: str

class PagerDutyIntegrationConfig(BaseModel):
    api_token: str
    service_ids: Optional[str] = None  # comma-separated
    team_ids: Optional[str] = None  # comma-separated

class Aws(BaseModel):
    access_key: str
    secrete_access: str
    region: str
    instance_id: str

class IncidentMail(BaseModel):
    inc_number: str
    subject: str
    message: str

class RequestBody(BaseModel):
    Aws: Aws
    Mail: IncidentMail  
    
class Incident(BaseModel):
    # NOTE: This model is used by /incidentAdd.
    # Keep fields backward-compatible with existing UI flows, while adding
    # optional external-* fields to support PagerDuty (and other sources).
    id: Optional[Union[int, str]] = None

    # Core (existing)
    short_description: str
    tag_id: Optional[str] = None
    state: Optional[str] = None

    # Internal incident correlation key used by worker + Results table.
    # For PagerDuty you can pass this explicitly, or let /incidentAdd derive it.
    inc_number: Optional[str] = None

    # Service link (new)
    service_id: Optional[str] = None
    
    # FQDN from CMDB
    fqdn: Optional[str] = None

    # External linkage (PagerDuty / ServiceNow / etc.)
    # Recommended values: 'manual' | 'servicenow' | 'pagerduty'
    source: Optional[str] = None
    external_id: Optional[str] = None
    external_number: Optional[str] = None
    external_url: Optional[str] = None
    external_status: Optional[str] = None
    external_urgency: Optional[str] = None
    external_service: Optional[str] = None
    external_created_at: Optional[datetime] = None
    external_updated_at: Optional[datetime] = None
    external_payload: Optional[Dict[str, Any]] = None
    # Alert type for escalation matrix (e.g., critical, high, medium, low)
    alert_type: Optional[str] = None


class AlertTypeEscalation(BaseModel):
    """Alert type escalation matrix"""
    id: Optional[str] = None
    alert_type_id: str
    alert_type_name: Optional[str] = None
    escalation_level: int = 1
    notification_channels: List[str] = ["email"]
    notification_destination: Optional[str] = None  # Email address or Slack channel name
    escalation_timeout_minutes: int = 30
    auto_escalate: bool = True
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class AlertTypeEscalationUpdate(BaseModel):
    """Alert type escalation update model"""
    alert_type_name: Optional[str] = None
    escalation_level: Optional[int] = None
    notification_channels: Optional[List[str]] = None
    notification_destination: Optional[str] = None  # Email address or Slack channel name
    escalation_timeout_minutes: Optional[int] = None
    auto_escalate: Optional[bool] = None

class Mesage(BaseModel):
    content: str
    session_id: Optional[str] = None
    # Context for re-formatting requests
    previous_data: Optional[Any] = None
    previous_data_type: Optional[str] = None
    format_request: Optional[str] = None

class ChatSession(BaseModel):
    id: Optional[str] = None
    user_id: Optional[str] = None
    title: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

class CreateChatSession(BaseModel):
    title: Optional[str] = None

class ChangeRequest(BaseModel):
    id: Optional[int] = None
    title: str
    description: Optional[str] = None
    service_id: Optional[str] = None
    priority: str = "medium"
    status: str = "draft"
    requester_id: str
    scheduled_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

class CreateChangeRequest(BaseModel):
    title: str
    description: Optional[str] = None
    service_id: Optional[str] = None
    priority: str = "medium"
    scheduled_at: Optional[datetime] = None

class UpdateChangeRequest(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    service_id: Optional[str] = None
    priority: Optional[str] = None
    scheduled_at: Optional[datetime] = None
    status: Optional[str] = None

class PendingAction(BaseModel):
    id: Optional[int] = None
    action_type: str
    description: Optional[str] = None
    payload: dict = {}
    status: str = "pending"
    requested_by: str = "system"
    approved_by: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

class CreatePendingAction(BaseModel):
    action_type: str
    description: Optional[str] = None
    payload: dict = {}
    requested_by: str = "system"
