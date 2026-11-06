CREATE TABLE quarantine (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  original_path TEXT NOT NULL,
  quarantine_path TEXT NOT NULL UNIQUE,
  threat_name TEXT NOT NULL,
  detection_date TEXT NOT NULL,
  file_size INTEGER NOT NULL,
  file_hash TEXT NOT NULL,
  original_permissions INTEGER NOT NULL DEFAULT 420,
  state TEXT NOT NULL DEFAULT 'active'
);
INSERT INTO quarantine (original_path, quarantine_path, threat_name, detection_date,
file_size, file_hash)
VALUES ('/home/user/Downloads/invoice.pdf.exe', @PAYLOAD_PATH@, 'Win.Trojan.Agent',
'2026-11-04T12:00:00.000Z', 15, 'c51d9cab89aec430d3274a51bbb930e124935ca08ab6f20d46e1c44651f46497');
