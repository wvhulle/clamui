CREATE TABLE IF NOT EXISTS file_contents (
    content_sha256 TEXT PRIMARY KEY
        CHECK (length(content_sha256) = 64 AND content_sha256 NOT GLOB '*[^0-9a-f]*'),
    byte_size INTEGER NOT NULL CHECK (byte_size >= 0)
);
CREATE TABLE IF NOT EXISTS quarantine (
    entry_id INTEGER PRIMARY KEY AUTOINCREMENT,
    original_path BLOB NOT NULL,
    quarantine_path BLOB NOT NULL UNIQUE,
    content_sha256 TEXT NOT NULL REFERENCES file_contents (content_sha256),
    detection_date TEXT NOT NULL CHECK (detection_date GLOB
        '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]*Z'),
    original_permissions INTEGER NOT NULL CHECK (original_permissions BETWEEN 0 AND 511)
);
CREATE INDEX IF NOT EXISTS idx_quarantine_detection_date ON quarantine (detection_date);
CREATE INDEX IF NOT EXISTS idx_quarantine_original_path ON quarantine (original_path);
CREATE INDEX IF NOT EXISTS idx_quarantine_content_sha256 ON quarantine (content_sha256);
CREATE TABLE IF NOT EXISTS quarantine_signatures (
    entry_id INTEGER PRIMARY KEY REFERENCES quarantine (entry_id) ON DELETE CASCADE,
    signature_name TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS quarantine_pending (
    quarantine_path BLOB PRIMARY KEY,
    original_path BLOB NOT NULL,
    byte_size INTEGER NOT NULL CHECK (byte_size >= 0),
    original_permissions INTEGER NOT NULL CHECK (original_permissions BETWEEN 0 AND 511)
);
CREATE TABLE IF NOT EXISTS pending_payload_hashes (
    quarantine_path BLOB PRIMARY KEY
        REFERENCES quarantine_pending (quarantine_path) ON DELETE CASCADE,
    content_sha256 TEXT NOT NULL
        CHECK (length(content_sha256) = 64 AND content_sha256 NOT GLOB '*[^0-9a-f]*')
);
CREATE TABLE IF NOT EXISTS pending_signatures (
    quarantine_path BLOB PRIMARY KEY
        REFERENCES quarantine_pending (quarantine_path) ON DELETE CASCADE,
    signature_name TEXT NOT NULL
);
