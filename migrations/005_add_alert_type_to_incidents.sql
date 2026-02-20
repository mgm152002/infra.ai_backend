-- Add alert_type_id to Incidents table
ALTER TABLE "Incidents" 
ADD COLUMN IF NOT EXISTS "alert_type_id" INTEGER REFERENCES "alert_types"("id") ON DELETE SET NULL;

-- Index for performance
CREATE INDEX IF NOT EXISTS "idx_incidents_alert_type_id" ON "Incidents"("alert_type_id");
