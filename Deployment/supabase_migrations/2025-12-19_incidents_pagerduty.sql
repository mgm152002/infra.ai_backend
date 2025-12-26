-- Extend the Incidents table to support storing incidents from external sources
-- (e.g. PagerDuty) alongside existing ServiceNow/manual incidents.
--
-- This script is intended for Supabase (Postgres) and is idempotent.

begin;

-- 1) External source + identifiers
alter table "Incidents"
  add column if not exists "source" text not null default 'manual';

alter table "Incidents"
  add column if not exists "external_id" text;

alter table "Incidents"
  add column if not exists "external_number" text;

alter table "Incidents"
  add column if not exists "external_url" text;

-- 2) External status + routing metadata (PagerDuty-style)
alter table "Incidents"
  add column if not exists "external_status" text;

alter table "Incidents"
  add column if not exists "external_urgency" text;

alter table "Incidents"
  add column if not exists "external_service" text;

-- 3) External timestamps
alter table "Incidents"
  add column if not exists "external_created_at" timestamptz;

alter table "Incidents"
  add column if not exists "external_updated_at" timestamptz;

-- 4) Store the raw external payload for traceability/debugging.
--    (For PagerDuty, store the raw "incident" object from /incidents/{id}.)
alter table "Incidents"
  add column if not exists "external_payload" jsonb;

-- 5) Optional safety constraint for known sources.
--    Uses NOT VALID so it won't fail on legacy rows if you already have unexpected values.
--    You can validate later after cleanup.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'incidents_source_check'
  ) THEN
    alter table "Incidents"
      add constraint incidents_source_check
      check ("source" in ('manual', 'servicenow', 'pagerduty'))
      not valid;
  END IF;
END $$;

-- 6) Helpful indexes for querying/importing external incidents.
create index if not exists "Incidents_source_idx" on "Incidents" ("source");
create index if not exists "Incidents_source_external_id_idx" on "Incidents" ("source", "external_id");

commit;
