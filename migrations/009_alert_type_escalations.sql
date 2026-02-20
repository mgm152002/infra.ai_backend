-- Create alert_type_escalations table for escalation matrix
CREATE TABLE IF NOT EXISTS alert_type_escalations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_type_id VARCHAR(255) NOT NULL UNIQUE,
    alert_type_name VARCHAR(255),
    escalation_level INTEGER DEFAULT 1,
    notification_channels TEXT[] DEFAULT ARRAY['email'],
    escalation_timeout_minutes INTEGER DEFAULT 30,
    auto_escalate BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Add indexes
CREATE INDEX IF NOT EXISTS idx_alert_type_escalations_alert_type ON alert_type_escalations(alert_type_id);

-- Add escalation columns to Incidents table
ALTER TABLE IF EXISTS incidents 
ADD COLUMN IF NOT EXISTS escalation_level INTEGER,
ADD COLUMN IF NOT EXISTS escalation_reason TEXT,
ADD COLUMN IF NOT EXISTS alert_type VARCHAR(255);

-- Create sample escalation types (can be customized per organization)
INSERT INTO alert_type_escalations (alert_type_id, alert_type_name, escalation_level, notification_channels, escalation_timeout_minutes) VALUES
    ('critical', 'Critical/P1', 3, ARRAY['slack', 'pagerduty', 'email'], 15),
    ('high', 'High/P2', 2, ARRAY['slack', 'email'], 30),
    ('medium', 'Medium/P3', 1, ARRAY['email'], 60),
    ('low', 'Low/P4', 0, ARRAY['email'], 120)
ON CONFLICT (alert_type_id) DO NOTHING;
