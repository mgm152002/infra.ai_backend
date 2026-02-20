-- Integrations Configuration (if not using Infisical solely)
-- We will use this table for non-sensitive config or just use Infisical for secrets.
-- For now, let's assume we might want to store some integration metadata here.
CREATE TABLE IF NOT EXISTS integrations_config (
    id SERIAL PRIMARY KEY,
    integration_name VARCHAR(50) NOT NULL UNIQUE, -- e.g., 'slack', 'email', 'jira'
    config JSONB DEFAULT '{}'::jsonb, -- Store non-sensitive configuration
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Alert Types
CREATE TABLE IF NOT EXISTS alert_types (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    priority VARCHAR(20) DEFAULT 'medium', -- low, medium, high, critical
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Escalation Rules
CREATE TABLE IF NOT EXISTS escalation_rules (
    id SERIAL PRIMARY KEY,
    alert_type_id INTEGER REFERENCES alert_types(id) ON DELETE CASCADE,
    level INTEGER NOT NULL, -- 1, 2, 3...
    wait_time_minutes INTEGER DEFAULT 0, -- Time to wait before escalating
    contact_type VARCHAR(20) NOT NULL, -- email, slack
    contact_destination VARCHAR(255) NOT NULL, -- email address or slack channel ID
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Change Requests
CREATE TABLE IF NOT EXISTS change_requests (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    service_id VARCHAR(100), -- ID of the service/CI being changed
    priority VARCHAR(20) DEFAULT 'medium',
    status VARCHAR(50) DEFAULT 'draft', -- draft, pending_approval, approved, rejected, completed
    requester_id VARCHAR(100) NOT NULL, -- User ID of the requester
    scheduled_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Approvals
CREATE TABLE IF NOT EXISTS approvals (
    id SERIAL PRIMARY KEY,
    change_request_id INTEGER REFERENCES change_requests(id) ON DELETE CASCADE,
    approver_id VARCHAR(100) NOT NULL, -- User ID of the approver
    status VARCHAR(50) DEFAULT 'pending', -- pending, approved, rejected
    comments TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- RCA Reports
CREATE TABLE IF NOT EXISTS rca_reports (
    id SERIAL PRIMARY KEY,
    incident_id VARCHAR(100) NOT NULL, -- Link to Incidents table (assuming inc_number or id is a string/int)
    report_content TEXT, -- The generated RCA content (Markdown/HTML)
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    generated_by VARCHAR(50) DEFAULT 'system' -- system or user_id
);

-- Pending Actions (Human in the Loop)
CREATE TABLE IF NOT EXISTS pending_actions (
    id SERIAL PRIMARY KEY,
    action_type VARCHAR(100) NOT NULL, -- e.g., 'RESTART_SERVICE', 'DELETE_RESOURCE'
    description TEXT,
    payload JSONB DEFAULT '{}'::jsonb, -- The data needed to execute the action
    status VARCHAR(50) DEFAULT 'pending', -- pending, approved, rejected, failed, completed
    requested_by VARCHAR(50) DEFAULT 'system', -- system, ai_agent, or user_id
    approved_by VARCHAR(100), -- User ID of approver
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- User Credentials (for Slack, Email, etc.)
CREATE TABLE IF NOT EXISTS user_credentials (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(100) NOT NULL,
    provider VARCHAR(50) NOT NULL, -- slack, email, jira
    credentials JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(user_id, provider)
);
