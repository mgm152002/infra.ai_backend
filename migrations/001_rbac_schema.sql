-- Migration: 001_rbac_schema.sql
-- Description: Create tables for Role-Based Access Control

-- 1. Roles Table
CREATE TABLE IF NOT EXISTS "Roles" (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

-- 2. Permissions Table
CREATE TABLE IF NOT EXISTS "Permissions" (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    resource TEXT NOT NULL, -- e.g., 'incidents', 'cmdb', 'settings'
    action TEXT NOT NULL,   -- e.g., 'read', 'write', 'delete'
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL,
    UNIQUE(resource, action)
);

-- 3. RolePermissions Table (Many-to-Many)
CREATE TABLE IF NOT EXISTS "RolePermissions" (
    role_id UUID REFERENCES "Roles"(id) ON DELETE CASCADE,
    permission_id UUID REFERENCES "Permissions"(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

-- 4. UserRoles Table (Many-to-Many)
-- Using BIGINT to match the existing Users table
CREATE TABLE IF NOT EXISTS "UserRoles" (
    user_id BIGINT REFERENCES "Users"(id) ON DELETE CASCADE,
    role_id UUID REFERENCES "Roles"(id) ON DELETE CASCADE,
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL,
    PRIMARY KEY (user_id, role_id)
);

-- Default Roles Seed
INSERT INTO "Roles" (name, description) VALUES
    ('admin', 'Full access to all resources'),
    ('operator', 'Can view and edit incidents'),
    ('viewer', 'Read-only access')
ON CONFLICT (name) DO NOTHING;

-- Default Permissions Seed (Example)
INSERT INTO "Permissions" (resource, action, description) VALUES
    ('incidents', 'read', 'View incidents'),
    ('incidents', 'write', 'Create and update incidents'),
    ('incidents', 'delete', 'Delete incidents'),
    ('cmdb', 'read', 'View CMDB'),
    ('cmdb', 'write', 'Update CMDB')
ON CONFLICT (resource, action) DO NOTHING;