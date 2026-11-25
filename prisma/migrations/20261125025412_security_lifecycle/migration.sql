CREATE TABLE "MfaLoginChallenge" (
    "userId" UUID NOT NULL,
    "challengeId" UUID NOT NULL,
    "sessionVersion" INTEGER NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "MfaLoginChallenge_pkey"
        PRIMARY KEY ("userId"),

    CONSTRAINT "MfaLoginChallenge_version_check"
        CHECK ("sessionVersion" >= 0)
);

CREATE UNIQUE INDEX "MfaLoginChallenge_challengeId_key"
ON "MfaLoginChallenge"("challengeId");

CREATE INDEX "MfaLoginChallenge_expiresAt_idx"
ON "MfaLoginChallenge"("expiresAt");

ALTER TABLE "MfaLoginChallenge"
ADD CONSTRAINT "MfaLoginChallenge_userId_fkey"
FOREIGN KEY ("userId")
REFERENCES "User"("id")
ON DELETE CASCADE
ON UPDATE CASCADE;

CREATE TABLE "RateLimitBucket" (
    "key" VARCHAR(64) NOT NULL,
    "hits" INTEGER NOT NULL,
    "blocked" BOOLEAN NOT NULL DEFAULT FALSE,
    "expiresAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "RateLimitBucket_pkey"
        PRIMARY KEY ("key"),

    CONSTRAINT "RateLimitBucket_hits_check"
        CHECK ("hits" > 0)
);

CREATE INDEX "RateLimitBucket_expiresAt_idx"
ON "RateLimitBucket"("expiresAt");
