-- Key epochs. sealed_keys = base64(nonce + AES-256-GCM(master key, JSON of the epoch's
-- ML-KEM + X25519 private key, FF1 key and DUKPT BDK)), with "epoch|N" as associated data.
CREATE TABLE epochs (
    epoch INTEGER PRIMARY KEY,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    pk_fingerprint TEXT NOT NULL,
    tx_counter BIGINT NOT NULL,
    sealed_keys TEXT NOT NULL
);

-- One row per card. doc holds BIN, last 4, network, KSN, the KEM envelope with the PAN, the
-- DUKPT MAC and timestamps. token is the current one.
CREATE TABLE records (
    record_id TEXT PRIMARY KEY,
    merchant_id TEXT NOT NULL,
    epoch INTEGER NOT NULL,
    token TEXT NOT NULL,
    doc TEXT NOT NULL
);

-- Every token that resolves, current or legacy (from before a rotation), per merchant.
CREATE TABLE tokens (
    merchant_id TEXT NOT NULL,
    token TEXT NOT NULL,
    record_id TEXT NOT NULL,
    legacy INTEGER NOT NULL,
    PRIMARY KEY (merchant_id, token)
);
CREATE INDEX tokens_record ON tokens (record_id);

-- HMAC-chained audit entries (JSON). seq is the chain position; the key stops two writers
-- from both appending after the same entry.
CREATE TABLE audit_log (
    seq BIGINT PRIMARY KEY,
    entry TEXT NOT NULL
);
