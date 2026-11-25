CREATE TABLE "AvatarCleanupJob" (
    "objectKey" TEXT NOT NULL,
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "notBefore" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AvatarCleanupJob_pkey" PRIMARY KEY ("objectKey")
);

CREATE INDEX "AvatarCleanupJob_notBefore_idx"
ON "AvatarCleanupJob"("notBefore");