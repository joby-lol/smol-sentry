-- abuseipdb reputation cache for blocks
CREATE TABLE
  "abuseipdb_blocks" (
    "ip" STRING NOT NULL COLLATE BINARY PRIMARY KEY,
    "score" INTEGER NOT NULL,
    "checked_at" INTEGER NOT NULL
  );

CREATE INDEX "idx_abuseipdb_blocks_checked_at" ON "abuseipdb" ("checked_at");

-- abuseipdb rate limiting for blocks
CREATE TABLE
  "abuseipdb_ratelimited_blocks" ("time" INTEGER NOT NULL);

CREATE INDEX "idx_abuseipdb_ratelimited_blocks_time" ON "abuseipdb_ratelimited_blocks" ("time");