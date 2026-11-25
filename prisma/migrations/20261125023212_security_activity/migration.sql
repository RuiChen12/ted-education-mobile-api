ALTER TYPE "SecurityEventType"
ADD VALUE 'PASSWORD_LOGIN_FAILED';

ALTER TYPE "SecurityEventType"
ADD VALUE 'MFA_VERIFICATION_FAILED';

ALTER TYPE "SecurityEventType"
ADD VALUE 'REFRESH_TOKEN_REPLAY';

CREATE INDEX "SecurityEvent_userId_type_createdAt_idx"
ON "SecurityEvent"("userId", "type", "createdAt");

CREATE INDEX "SecurityEvent_userId_createdAt_id_idx"
ON "SecurityEvent"("userId", "createdAt", "id");

CREATE INDEX "SecurityEvent_createdAt_idx"
ON "SecurityEvent"("createdAt");
