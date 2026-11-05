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
INSERT INTO background_detections VALUES
    (1, CAST(@UNRESOLVED_PATH@ AS BLOB), 'Win.Trojan.Agent-1', 1, 0, 1793869222, 1793869225, 6, '', 0),
    (2, CAST(@SCHEDULED_PATH@ AS BLOB), 'URLhaus.15711', 0, 1, 1793700000, 1793700000, 1, '', 0),
    (3, CAST('/home/alex/Downloads/old-report.pdf.exe' AS BLOB), 'Eicar-Test-Signature', 1, 0, 1793600000, 1793600002, 2, 'quarantined', 1793600100);
