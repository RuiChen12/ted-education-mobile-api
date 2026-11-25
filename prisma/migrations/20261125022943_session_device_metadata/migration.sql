ALTER TABLE "AuthSession"
ADD COLUMN "devicePlatform" VARCHAR(16),
ADD COLUMN "lastActiveAt" TIMESTAMP(3);

ALTER TABLE "AuthSession"
ADD CONSTRAINT "AuthSession_devicePlatform_check"
CHECK (
    "devicePlatform" IS NULL
    OR "devicePlatform" IN ('android', 'ios', 'web')
);
