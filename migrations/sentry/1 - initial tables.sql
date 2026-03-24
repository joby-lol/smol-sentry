-- signals table holds all the raw data
CREATE TABLE
  "signals" (
    "id" INTEGER NOT NULL,
    "ip" STRING NOT NULL COLLATE BINARY,
    "type" STRING NOT NULL,
    "malicious" INTEGER NOT NULL,
    "time" INTEGER NOT NULL,
    PRIMARY KEY ("id" AUTOINCREMENT)
  );

CREATE INDEX "idx_signal_ip" ON "signals" ("ip");

CREATE INDEX "idx_signal_type" ON "signals" ("type");

CREATE INDEX "idx_signal_malicious" ON "signals" ("malicious");

CREATE INDEX "idx_signal_time" ON "signals" ("time");

-- verdicts table holds all requests for an IP to be challenged or fully banned
CREATE TABLE
  "verdicts" (
    "id" INTEGER NOT NULL,
    "ip" STRING NOT NULL COLLATE BINARY,
    "ban" INTEGER NOT NULL,
    "reason" STRING NOT NULL,
    "time" INTEGER NOT NULL,
    "expires" INTEGER NOT NULL,
    "released" INTEGER,
    PRIMARY KEY ("id" AUTOINCREMENT)
  );

CREATE INDEX "idx_verdicts_ip" ON "verdicts" ("ip");

CREATE INDEX "idx_verdicts_time" ON "verdicts" ("time");

CREATE INDEX "idx_verdicts_ban" ON "verdicts" ("ban");

CREATE INDEX "idx_verdicts_expires" ON "verdicts" ("expires");

CREATE INDEX "idx_verdicts_released" ON "verdicts" ("released");