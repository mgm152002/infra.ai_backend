-- Add notification_destination column to alert_type_escalations table
ALTER TABLE alert_type_escalations 
ADD COLUMN IF NOT EXISTS notification_destination TEXT;
