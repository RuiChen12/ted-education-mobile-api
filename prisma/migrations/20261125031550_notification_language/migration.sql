ALTER TABLE "SecurityNotification"
ADD COLUMN "language" VARCHAR(8) NOT NULL DEFAULT 'en';

ALTER TABLE "SecurityNotification"
ADD CONSTRAINT "SecurityNotification_language_check"
CHECK ("language" IN ('en', 'zh', 'ja', 'ko', 'es'));
