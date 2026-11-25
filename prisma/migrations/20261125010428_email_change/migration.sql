ALTER TYPE "SecurityEventType" ADD VALUE 'EMAIL_CHANGED';

CREATE TABLE "EmailChangeRequest" (
    "userId" UUID NOT NULL,
    "requestId" UUID NOT NULL,
    "sessionId" UUID NOT NULL,
    "sessionVersion" INTEGER NOT NULL,
    "oldEmail" VARCHAR(254) NOT NULL,
    "newEmail" VARCHAR(254) NOT NULL,
    "oldCodeHash" VARCHAR(64) NOT NULL,
    "newCodeHash" VARCHAR(64) NOT NULL,
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "sentAt" TIMESTAMP(3) NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "sentInWindow" INTEGER NOT NULL,
    "windowStartedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "EmailChangeRequest_pkey" PRIMARY KEY ("userId")
);

CREATE UNIQUE INDEX "EmailChangeRequest_requestId_key"
ON "EmailChangeRequest"("requestId");

CREATE INDEX "EmailChangeRequest_expiresAt_idx"
ON "EmailChangeRequest"("expiresAt");

ALTER TABLE "EmailChangeRequest"
ADD CONSTRAINT "EmailChangeRequest_userId_fkey"
FOREIGN KEY ("userId")
REFERENCES "User"("id")
ON DELETE CASCADE ON UPDATE CASCADE;