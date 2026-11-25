CREATE TYPE "GoogleSensitiveAction" AS ENUM (
    'SET_PASSWORD',
    'EXPORT_DATA',
    'DELETE_ACCOUNT'
);

CREATE TABLE "GoogleActionChallenge" (
    "userId" UUID NOT NULL,
    "requestId" UUID NOT NULL,
    "sessionId" UUID NOT NULL,
    "sessionVersion" INTEGER NOT NULL,
    "action" "GoogleSensitiveAction" NOT NULL,
    "googleSubject" VARCHAR(255) NOT NULL,
    "email" VARCHAR(254) NOT NULL,
    "codeHash" VARCHAR(64) NOT NULL,
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "sentAt" TIMESTAMP(3) NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "consumedAt" TIMESTAMP(3),
    "sentInWindow" INTEGER NOT NULL,
    "windowStartedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "GoogleActionChallenge_pkey"
        PRIMARY KEY ("userId")
);

CREATE UNIQUE INDEX "GoogleActionChallenge_requestId_key"
    ON "GoogleActionChallenge"("requestId");

CREATE INDEX "GoogleActionChallenge_expiresAt_idx"
    ON "GoogleActionChallenge"("expiresAt");

ALTER TABLE "GoogleActionChallenge"
    ADD CONSTRAINT "GoogleActionChallenge_userId_fkey"
    FOREIGN KEY ("userId")
    REFERENCES "User"("id")
    ON DELETE CASCADE
    ON UPDATE CASCADE;

ALTER TABLE "GoogleActionChallenge"
    ADD CONSTRAINT "GoogleActionChallenge_attempts_check"
    CHECK ("attempts" >= 0 AND "attempts" <= 5);

ALTER TABLE "GoogleActionChallenge"
    ADD CONSTRAINT "GoogleActionChallenge_send_limit_check"
    CHECK ("sentInWindow" >= 1 AND "sentInWindow" <= 5);

ALTER TABLE "GoogleActionChallenge"
    ADD CONSTRAINT "GoogleActionChallenge_expiration_check"
    CHECK ("expiresAt" > "sentAt");
