-- Migration: 012_add_escalation_indexes.sql
-- Description: Add indexes specifically for escalation monitor queries to prevent timeouts
-- This migration adds composite indexes optimized for the escalation monitoring queries

-- Composite index for escalation monitor: state filtering + ordering by updated_at
-- This helps the query that filters by state NOT IN ('Resolved', 'Closed')
-- and orders by updated_at for determining which incidents need escalation
CREATE INDEX IF NOT EXISTS "Incidents_state_updated_at_idx" ON "Incidents"(state, updated_at DESC);

-- Index for alert_type_id lookups in escalation (used frequently)
CREATE INDEX IF NOT EXISTS "Incidents_alert_type_id_idx" ON "Incidents"(alert_type_id);

-- Composite index for user_id + state (for incident queries by user)
CREATE INDEX IF NOT EXISTS "Incidents_user_id_state_idx" ON "Incidents"(user_id, state);

-- Index for external_urgency lookups (used in escalation)
CREATE INDEX IF NOT EXISTS "Incidents_external_urgency_idx" ON "Incidents"(external_urgency);

-- Index for inc_number lookups (frequently used in joins and updates)
CREATE INDEX IF NOT EXISTS "Incidents_inc_number_idx" ON "Incidents"(inc_number);

-- Index for created_at sorting (for time-based queries)
CREATE INDEX IF NOT EXISTS "Incidents_created_at_idx" ON "Incidents"(created_at DESC);

-- Add index on external_payload for escalation_level extraction (JSONB)
-- This is a partial index for incidents that have escalation_level set
CREATE INDEX IF NOT EXISTS "Incidents_external_payload_escalation_idx" ON "Incidents"(((external_payload->>'escalation_level'))) 
WHERE external_payload IS NOT NULL;

-- Index for escalation_rules table (alert_type_id + level)
CREATE INDEX IF NOT EXISTS "escalation_rules_alert_type_level_idx" ON "escalation_rules"(alert_type_id, level);

-- Index for alert_types table (priority lookups)
CREATE INDEX IF NOT EXISTS "alert_types_priority_idx" ON "alert_types"(priority);

-- Analyze tables to update statistics (helps query planner)
ANALYZE "Incidents";
ANALYZE "escalation_rules";
ANALYZE "alert_types";
