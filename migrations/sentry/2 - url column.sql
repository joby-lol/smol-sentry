-- add url column to signals table
ALTER TABLE "signals"
ADD COLUMN "url" STRING COLLATE NOCASE;

CREATE INDEX "idx_signal_url" ON "signals" ("url");