ALTER TABLE "User"
ADD COLUMN "passwordResetSentInWindow" INTEGER NOT NULL DEFAULT 0,
ADD COLUMN "passwordResetWindowStartedAt" TIMESTAMP(3),
ADD COLUMN "passwordResetLastSentAt" TIMESTAMP(3);

ALTER TABLE "User"
ADD CONSTRAINT "User_passwordResetSentInWindow_check"
CHECK (
    "passwordResetSentInWindow" >= 0
    AND "passwordResetSentInWindow" <= 5
);
