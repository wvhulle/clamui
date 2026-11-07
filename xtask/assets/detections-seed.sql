INSERT INTO background_detections (file_path, signature_name, detection_id, detection_sources,
first_seen_unix, last_seen_unix, sighting_count) VALUES
    (CAST(@UNRESOLVED_PATH@ AS BLOB), 'Win.Trojan.Agent-1', 1, 'on_access', 1793869222, 1793869225, 6),
    (CAST(@SCHEDULED_PATH@ AS BLOB), 'URLhaus.15711', 2, 'scheduled_scan', 1793700000, 1793700000, 1),
    (CAST('/home/alex/Downloads/old-report.pdf.exe' AS BLOB), 'Eicar-Test-Signature', 3, 'on_access', 1793600000, 1793600002, 2);
INSERT INTO detection_resolutions (file_path, signature_name, resolution_kind, resolved_at_unix)
VALUES (CAST('/home/alex/Downloads/old-report.pdf.exe' AS BLOB), 'Eicar-Test-Signature', 'quarantined', 1793600100);
