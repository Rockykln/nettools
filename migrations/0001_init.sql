-- Root server measurements taken by the cron trigger (kept 7 days).
CREATE TABLE root_samples (
  ts INTEGER NOT NULL,          -- unix seconds
  colo TEXT NOT NULL,           -- Cloudflare data center that ran the check
  root TEXT NOT NULL,           -- letter A-M
  connect_ms INTEGER,
  query_ms INTEGER,
  serial INTEGER,
  ok INTEGER NOT NULL           -- 1 answered, 0 failed
);
CREATE INDEX idx_root_samples_ts ON root_samples (ts);
