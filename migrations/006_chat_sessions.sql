-- Chat Sessions Table
CREATE TABLE IF NOT EXISTS "ChatSessions" (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES "Users"(id) ON DELETE CASCADE,
    title VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Add session_id to ChatHistory
ALTER TABLE "ChatHistory"
ADD COLUMN IF NOT EXISTS "session_id" UUID REFERENCES "ChatSessions"(id) ON DELETE CASCADE;

-- Index for performance
CREATE INDEX IF NOT EXISTS "idx_chathistory_session_id" ON "ChatHistory"("session_id");
