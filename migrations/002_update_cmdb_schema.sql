-- Migration: 002_update_cmdb_schema.sql
-- Description: Update CMDB table to support external sync (e.g., ServiceNow) and robust asset details

ALTER TABLE "CMDB"
ADD COLUMN IF NOT EXISTS "sys_id" TEXT UNIQUE,
ADD COLUMN IF NOT EXISTS "source" TEXT DEFAULT 'manual',
ADD COLUMN IF NOT EXISTS "last_sync" TIMESTAMPTZ,
ADD COLUMN IF NOT EXISTS "raw_data" JSONB,
ADD COLUMN IF NOT EXISTS "manufacturer" TEXT,
ADD COLUMN IF NOT EXISTS "model_id" TEXT,
ADD COLUMN IF NOT EXISTS "serial_number" TEXT,
ADD COLUMN IF NOT EXISTS "mac_address" TEXT,
ADD COLUMN IF NOT EXISTS "location" TEXT,
ADD COLUMN IF NOT EXISTS "install_status" TEXT,
ADD COLUMN IF NOT EXISTS "assigned_to" TEXT;

COMMENT ON COLUMN "CMDB"."sys_id" IS 'External system identifier (e.g., ServiceNow sys_id)';
COMMENT ON COLUMN "CMDB"."source" IS 'Source of the CI item (manual, servicenow, etc.)';
COMMENT ON COLUMN "CMDB"."manufacturer" IS 'Manufacturer of the CI';
COMMENT ON COLUMN "CMDB"."model_id" IS 'Model of the CI';
COMMENT ON COLUMN "CMDB"."serial_number" IS 'Serial number';
COMMENT ON COLUMN "CMDB"."mac_address" IS 'MAC address of the network interface';
COMMENT ON COLUMN "CMDB"."location" IS 'Physical location';
COMMENT ON COLUMN "CMDB"."install_status" IS 'Installation status (installed, retired, etc.)';
COMMENT ON COLUMN "CMDB"."assigned_to" IS 'User assigned to this CI';
