INSERT INTO file_contents (content_sha256, byte_size)
VALUES ('c51d9cab89aec430d3274a51bbb930e124935ca08ab6f20d46e1c44651f46497', 15);
INSERT INTO quarantine (original_path, quarantine_path, content_sha256, detection_date,
original_permissions)
VALUES (CAST('/home/user/Downloads/invoice.pdf.exe' AS BLOB), CAST(@PAYLOAD_PATH@ AS BLOB),
'c51d9cab89aec430d3274a51bbb930e124935ca08ab6f20d46e1c44651f46497',
'2026-11-04T12:00:00.000Z', 420);
INSERT INTO quarantine_signatures (entry_id, signature_name)
SELECT entry_id, 'Win.Trojan.Agent' FROM quarantine;
