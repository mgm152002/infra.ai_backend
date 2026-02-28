-- Migration: 011_add_performance_indexes.sql
-- Description: Add indexes for better query performance on Jobs, Incidents, and Users tables

-- Users table indexes for faster authentication and email lookups
CREATE INDEX IF NOT EXISTS "Users_email_idx" ON "Users"(email);
CREATE INDEX IF NOT EXISTS "Users_clerk_id_idx" ON "Users"(clerk_id);
CREATE INDEX IF NOT EXISTS "Jobs_user_id_status_idx" ON "Jobs"(user_id, status);
CREATE INDEX IF NOT EXISTS "Jobs_created_at_idx" ON "Jobs"(created_at DESC);

-- Incidents table indexes for faster incident queries
CREATE INDEX IF NOT EXISTS "Incidents_user_id_idx" ON "Incidents"(user_id);
CREATE INDEX IF NOT EXISTS "Incidents_user_id_created_at_idx" ON "Incidents"(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS "Incidents_inc_number_idx" ON "Incidents"(inc_number);
CREATE INDEX IF NOT EXISTS "Incidents_state_idx" ON "Incidents"(state);

-- Users table indexes for faster email lookups
CREATE INDEX IF NOT EXISTS "Users_email_idx" ON "Users"(email);

-- CMDB table indexes
CREATE INDEX IF NOT EXISTS "CMDB_user_id_idx" ON "CMDB"(user_id);
CREATE INDEX IF NOT EXISTS "CMDB_tag_id_user_id_idx" ON "CMDB"(tag_id, user_id);

-- Results table indexes
CREATE INDEX IF NOT EXISTS "Results_inc_number_user_id_idx" ON "Results"(inc_number, user_id);
