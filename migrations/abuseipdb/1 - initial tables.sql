-- abuseipdb reputation cache
CREATE TABLE
  "abuseipdb" (
    "ip" STRING NOT NULL COLLATE BINARY PRIMARY KEY,
    "score" INTEGER NOT NULL,
    "checked_at" INTEGER NOT NULL
  );

CREATE INDEX "idx_abuseipdb_checked_at" ON "abuseipdb" ("checked_at");

-- abuseipdb rate limiting
CREATE TABLE
  "abuseipdb_ratelimited" ("time" INTEGER NOT NULL);

CREATE INDEX "idx_abuseipdb_ratelimited_time" ON "abuseipdb_ratelimited" ("time");