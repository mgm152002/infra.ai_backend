-- Migration: Add clerk_id column to Users table
-- This allows looking up users by their Clerk user ID from JWT 'sub' claim

-- Add clerk_id column if it doesn't exist
ALTER TABLE "Users" 
ADD COLUMN IF NOT EXISTS clerk_id VARCHAR(255) UNIQUE;

-- Create index for faster lookups
CREATE INDEX IF NOT EXISTS idx_users_clerk_id ON "Users" (clerk_id);

-- Comment explaining the column
COMMENT ON COLUMN "Users".clerk_id IS 'Clerk user ID from JWT sub claim, used for authentication lookup';
