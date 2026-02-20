-- Create Problem Records table
CREATE TABLE IF NOT EXISTS "problem_records" (
    "id" SERIAL PRIMARY KEY,
    "title" TEXT NOT NULL,
    "description" TEXT,
    "root_cause" TEXT,
    "workaround" TEXT,
    "permanent_fix" TEXT,
    "status" TEXT DEFAULT 'open', -- open, root_cause_identified, fix_in_progress, resolved, closed
    "priority" TEXT DEFAULT 'medium',
    "created_by" TEXT, -- User ID or Email
    "assigned_to" TEXT, -- User ID or Email
    "created_at" TIMESTAMPTZ DEFAULT NOW(),
    "updated_at" TIMESTAMPTZ DEFAULT NOW()
);

-- Add linkage to Incidents (One Problem can have multiple Incidents, but for simplicity here, maybe just link Incident to Problem)
-- OR: Incident has a `problem_id` foreign key.
-- NOTE: Table names are case sensitive in Supabase if created with quotes. Existing table is "Incidents".
ALTER TABLE "Incidents" ADD COLUMN IF NOT EXISTS "problem_id" INTEGER REFERENCES "problem_records"("id");

-- Create indexes
CREATE INDEX IF NOT EXISTS "idx_problem_records_status" ON "problem_records"("status");
CREATE INDEX IF NOT EXISTS "idx_incidents_problem_id" ON "Incidents"("problem_id");
