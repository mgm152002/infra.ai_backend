-- Migration: 003_jobs_table.sql
-- Description: Create Jobs table for tracking background task progress

CREATE TABLE IF NOT EXISTS "Jobs" (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id TEXT NOT NULL,
    task_type TEXT NOT NULL, -- e.g., 'snow_sync'
    status TEXT NOT NULL DEFAULT 'pending', -- pending, running, completed, failed
    progress INTEGER DEFAULT 0,
    total_items INTEGER DEFAULT 0,
    processed_items INTEGER DEFAULT 0,
    details JSONB,
    created_at TIMESTAMPTZ DEFAULT timezone('utc'::text, now()) NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT timezone('utc'::text, now()) NOT NULL
);

COMMENT ON COLUMN "Jobs".user_id IS 'User who initiated the job (auth0/clerk id)';
COMMENT ON COLUMN "Jobs".progress IS 'Percentage complete (0-100)';
