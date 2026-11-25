CREATE TABLE "SecurityNotification" (
    "id" UUID NOT NULL,
    "userId" UUID NOT NULL,
    "recipient" VARCHAR(254) NOT NULL,
    "kind" "SecurityEventType" NOT NULL,
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "notBefore" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "claimId" UUID,
    "deliveredAt" TIMESTAMP(3),
    "failedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "SecurityNotification_pkey"
        PRIMARY KEY ("id"),

    CONSTRAINT "SecurityNotification_attempts_check"
        CHECK ("attempts" >= 0 AND "attempts" <= 8),

    CONSTRAINT "SecurityNotification_terminal_check"
        CHECK ("deliveredAt" IS NULL OR "failedAt" IS NULL)
);

CREATE INDEX "SecurityNotification_deliveredAt_failedAt_notBefore_idx"
ON "SecurityNotification"("deliveredAt", "failedAt", "notBefore");

CREATE INDEX "SecurityNotification_userId_idx"
ON "SecurityNotification"("userId");

CREATE INDEX "SecurityNotification_createdAt_idx"
ON "SecurityNotification"("createdAt");

ALTER TABLE "SecurityNotification"
ADD CONSTRAINT "SecurityNotification_userId_fkey"
FOREIGN KEY ("userId")
REFERENCES "User"("id")
ON DELETE CASCADE
ON UPDATE CASCADE;
