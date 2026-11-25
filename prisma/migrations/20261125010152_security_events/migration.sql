CREATE TYPE "SecurityEventType" AS ENUM (
    'SESSION_CREATED',
    'SESSION_REVOKED',
    'SIGNED_OUT',
    'ALL_SESSIONS_REVOKED',
    'PASSWORD_CHANGED',
    'PASSWORD_RESET',
    'MFA_ENABLED',
    'MFA_DISABLED',
    'RECOVERY_CODES_REGENERATED'
);

CREATE TABLE "SecurityEvent" (
    "id" UUID NOT NULL,
    "userId" UUID NOT NULL,
    "type" "SecurityEventType" NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "SecurityEvent_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "SecurityEvent_userId_createdAt_idx"
ON "SecurityEvent"("userId", "createdAt");

ALTER TABLE "SecurityEvent"
ADD CONSTRAINT "SecurityEvent_userId_fkey"
FOREIGN KEY ("userId")
REFERENCES "User"("id")
ON DELETE CASCADE
ON UPDATE CASCADE;