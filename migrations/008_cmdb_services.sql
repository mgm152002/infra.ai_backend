-- Migration: 008_cmdb_services.sql
-- Description: Add services table and service_id, fqdn columns to CMDB for organized infrastructure management

-- Create services table (global/shared)
CREATE TABLE IF NOT EXISTS "services" (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    service_type TEXT,  -- e.g., 'web', 'database', 'api', 'cache', 'storage'
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);

-- Add service_id column to CMDB table
ALTER TABLE "CMDB"
ADD COLUMN IF NOT EXISTS "service_id" UUID REFERENCES "services"(id),
ADD COLUMN IF NOT EXISTS "fqdn" TEXT;  -- Fully Qualified Domain Name

-- Add service_id column to Incidents table
ALTER TABLE "Incidents"
ADD COLUMN IF NOT EXISTS "service_id" UUID REFERENCES "services"(id);

-- Add index for faster service lookups
CREATE INDEX IF NOT EXISTS "idx_cmdb_service_id" ON "CMDB"(service_id);
CREATE INDEX IF NOT EXISTS "idx_incidents_service_id" ON "Incidents"(service_id);

-- Add some default services
INSERT INTO "services" (name, description, service_type) VALUES 
    ('Web Application', 'Frontend and backend web services', 'web'),
    ('Database', 'Database servers and clusters', 'database'),
    ('API Service', 'REST and GraphQL API endpoints', 'api'),
    ('Cache', 'Redis, Memcached caching services', 'cache'),
    ('Storage', 'File storage and object storage', 'storage'),
    ('Message Queue', 'RabbitMQ, Kafka message brokers', 'queue'),
    ('Monitoring', 'Prometheus, Grafana monitoring', 'monitoring')
ON CONFLICT (name) DO NOTHING;

-- Add foreign key constraint name for clarity
COMMENT ON TABLE "services" IS 'Global services that hosts belong to';
COMMENT ON COLUMN "CMDB"."service_id" IS 'Foreign key to services table';
COMMENT ON COLUMN "CMDB"."fqdn" IS 'Fully Qualified Domain Name of the host';
COMMENT ON COLUMN "Incidents"."service_id" IS 'Foreign key to services table for incident categorization';
