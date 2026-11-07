CREATE TABLE IF NOT EXISTS activity_entries (
    entry_id INTEGER PRIMARY KEY,
    started_at_unix INTEGER NOT NULL,
    activity_status TEXT NOT NULL CHECK (activity_status IN (
        'scan_clean', 'scan_infected', 'scan_failed', 'scan_cancelled', 'scan_skipped',
        'update_applied', 'update_already_current', 'update_requested',
        'update_result_unknown', 'update_failed', 'update_cancelled'
    )),
    duration_millis INTEGER NOT NULL CHECK (duration_millis >= 0),
    activity_output TEXT NOT NULL,
    UNIQUE (entry_id, activity_status)
);
CREATE TABLE IF NOT EXISTS scan_activities (
    entry_id INTEGER PRIMARY KEY,
    activity_status TEXT NOT NULL CHECK (activity_status IN (
        'scan_clean', 'scan_infected', 'scan_failed', 'scan_cancelled', 'scan_skipped'
    )),
    scan_origin TEXT NOT NULL
        CHECK (scan_origin IN ('manual_scan', 'scheduled_scan', 'device_scan')),
    CHECK (activity_status <> 'scan_skipped' OR scan_origin = 'scheduled_scan'),
    UNIQUE (entry_id, activity_status),
    FOREIGN KEY (entry_id, activity_status)
        REFERENCES activity_entries (entry_id, activity_status) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS scan_activity_targets (
    entry_id INTEGER NOT NULL REFERENCES scan_activities (entry_id) ON DELETE CASCADE,
    target_position INTEGER NOT NULL CHECK (target_position >= 0),
    target_path TEXT NOT NULL CHECK (target_path <> ''),
    PRIMARY KEY (entry_id, target_position)
);
CREATE TABLE IF NOT EXISTS scan_inspections (
    entry_id INTEGER PRIMARY KEY,
    activity_status TEXT NOT NULL CHECK (activity_status IN (
        'scan_clean', 'scan_infected', 'scan_failed', 'scan_cancelled'
    )),
    inspected_file_count INTEGER NOT NULL CHECK (inspected_file_count >= 0),
    UNIQUE (entry_id, activity_status),
    FOREIGN KEY (entry_id, activity_status)
        REFERENCES scan_activities (entry_id, activity_status) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS scan_threat_counts (
    entry_id INTEGER PRIMARY KEY,
    activity_status TEXT NOT NULL CHECK (activity_status = 'scan_infected'),
    threat_count INTEGER NOT NULL CHECK (threat_count > 0),
    FOREIGN KEY (entry_id, activity_status)
        REFERENCES scan_inspections (entry_id, activity_status) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS background_detections (
    detection_id INTEGER PRIMARY KEY,
    file_path BLOB NOT NULL,
    signature_name TEXT NOT NULL,
    found_on_access INTEGER NOT NULL,
    found_by_schedule INTEGER NOT NULL,
    first_seen_unix INTEGER NOT NULL,
    last_seen_unix INTEGER NOT NULL,
    sighting_count INTEGER NOT NULL,
    resolution TEXT NOT NULL,
    resolved_at_unix INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS detection_journal_position (
    position_row INTEGER PRIMARY KEY,
    journal_cursor TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS submissions (
    content_sha256 TEXT NOT NULL,
    submission_service TEXT NOT NULL
        CHECK (submission_service IN ('clamav', 'malware_bazaar', 'virustotal')),
    submission_kind TEXT NOT NULL
        CHECK (submission_kind IN ('false_positive', 'missed_malware', 'malware_sample')),
    file_name TEXT NOT NULL,
    submitted_at_unix INTEGER NOT NULL,
    submission_status TEXT NOT NULL,
    PRIMARY KEY (content_sha256, submission_service, submission_kind)
);
CREATE TABLE IF NOT EXISTS false_positive_signatures (
    content_sha256 TEXT NOT NULL,
    submission_service TEXT NOT NULL CHECK (submission_service = 'clamav'),
    submission_kind TEXT NOT NULL CHECK (submission_kind = 'false_positive'),
    reported_signature TEXT NOT NULL,
    PRIMARY KEY (content_sha256, submission_service, submission_kind),
    FOREIGN KEY (content_sha256, submission_service, submission_kind)
        REFERENCES submissions (content_sha256, submission_service, submission_kind)
        ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS clamav_review_settlements (
    content_sha256 TEXT NOT NULL,
    submission_service TEXT NOT NULL CHECK (submission_service = 'clamav'),
    submission_kind TEXT NOT NULL
        CHECK (submission_kind IN ('false_positive', 'missed_malware')),
    settled_database_version INTEGER,
    PRIMARY KEY (content_sha256, submission_service, submission_kind),
    FOREIGN KEY (content_sha256, submission_service, submission_kind)
        REFERENCES submissions (content_sha256, submission_service, submission_kind)
        ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS virustotal_analyses (
    content_sha256 TEXT NOT NULL,
    submission_service TEXT NOT NULL CHECK (submission_service = 'virustotal'),
    submission_kind TEXT NOT NULL CHECK (submission_kind = 'malware_sample'),
    analysis_id TEXT NOT NULL,
    PRIMARY KEY (content_sha256, submission_service, submission_kind),
    FOREIGN KEY (content_sha256, submission_service, submission_kind)
        REFERENCES submissions (content_sha256, submission_service, submission_kind)
        ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS virustotal_verdicts (
    content_sha256 TEXT NOT NULL,
    submission_service TEXT NOT NULL CHECK (submission_service = 'virustotal'),
    submission_kind TEXT NOT NULL CHECK (submission_kind = 'malware_sample'),
    malicious_count INTEGER NOT NULL CHECK (malicious_count >= 0),
    engine_count INTEGER NOT NULL CHECK (engine_count >= malicious_count),
    PRIMARY KEY (content_sha256, submission_service, submission_kind),
    FOREIGN KEY (content_sha256, submission_service, submission_kind)
        REFERENCES submissions (content_sha256, submission_service, submission_kind)
        ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS upload_refusals (
    content_sha256 TEXT NOT NULL,
    submission_service TEXT NOT NULL
        CHECK (submission_service IN ('malware_bazaar', 'virustotal')),
    submission_kind TEXT NOT NULL CHECK (submission_kind = 'malware_sample'),
    refusal_reason TEXT NOT NULL,
    PRIMARY KEY (content_sha256, submission_service, submission_kind),
    FOREIGN KEY (content_sha256, submission_service, submission_kind)
        REFERENCES submissions (content_sha256, submission_service, submission_kind)
        ON DELETE CASCADE
);
