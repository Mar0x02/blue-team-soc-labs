"""
correlation_state.py - SQLite state buat Fase 2 (full chain detection):
- checkpoint incremental (biar query ke Wazuh Indexer gak scan ulang data lama)
- dedup alert by alert_id (nyegah alert diproses dobel gara-gara overlap query)
- events: tier-1 micro-cluster -- alert dari sensor beda (auditd + Suricata dst) yang
  nangkep 1 AKSI NYATA yang sama (gap super rapat, hitungan detik)
- incidents: tier-2 -- gabungan beberapa event jadi 1 attack chain (rolling silence
  window, bukan window waktu tetap -- biar chain yang lambat/nyebar gak kepotong)
"""

import json
import sqlite3
import uuid
from datetime import datetime, timezone

DEFAULT_DB_PATH = "./correlation_state.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS checkpoint (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    last_checkpoint_ts TEXT
);

CREATE TABLE IF NOT EXISTS processed_alerts (
    alert_id TEXT PRIMARY KEY,
    host_name TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    rule_id TEXT,
    rule_level INTEGER,
    rule_description TEXT,
    source_type TEXT,
    key_fields TEXT,
    event_id TEXT
);

CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    host_name TEXT NOT NULL,
    first_seen_ts TEXT NOT NULL,
    last_seen_ts TEXT NOT NULL,
    incident_id TEXT
);

CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    host_name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    first_seen_ts TEXT NOT NULL,
    last_seen_ts TEXT NOT NULL,
    finalized_at TEXT
);

CREATE TABLE IF NOT EXISTS pending_exec_alerts (
    alert_id TEXT PRIMARY KEY,
    host_name TEXT NOT NULL,
    task_key TEXT,
    timestamp TEXT NOT NULL,
    rule_id TEXT,
    payload TEXT NOT NULL
);
"""


def get_connection(db_path: str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_checkpoint(conn: sqlite3.Connection) -> str | None:
    row = conn.execute("SELECT last_checkpoint_ts FROM checkpoint WHERE id = 1").fetchone()
    return row["last_checkpoint_ts"] if row else None


def set_checkpoint(conn: sqlite3.Connection, ts: str):
    conn.execute(
        "INSERT INTO checkpoint (id, last_checkpoint_ts) VALUES (1, ?) "
        "ON CONFLICT(id) DO UPDATE SET last_checkpoint_ts = excluded.last_checkpoint_ts",
        (ts,),
    )
    conn.commit()


def is_processed(conn: sqlite3.Connection, alert_id: str) -> bool:
    row = conn.execute("SELECT 1 FROM processed_alerts WHERE alert_id = ?", (alert_id,)).fetchone()
    return row is not None


def _find_open_event(conn: sqlite3.Connection, host_name: str, alert_ts: str, micro_window_seconds: int):
    row = conn.execute(
        "SELECT * FROM events WHERE host_name = ? ORDER BY last_seen_ts DESC LIMIT 1",
        (host_name,),
    ).fetchone()
    if row is None:
        return None
    gap = (datetime.fromisoformat(alert_ts) - datetime.fromisoformat(row["last_seen_ts"])).total_seconds()
    return row if 0 <= gap <= micro_window_seconds else None


def _find_open_incident(conn: sqlite3.Connection, host_name: str, alert_ts: str, silence_threshold_seconds: int):
    row = conn.execute(
        "SELECT * FROM incidents WHERE host_name = ? AND status = 'open' ORDER BY last_seen_ts DESC LIMIT 1",
        (host_name,),
    ).fetchone()
    if row is None:
        return None
    gap = (datetime.fromisoformat(alert_ts) - datetime.fromisoformat(row["last_seen_ts"])).total_seconds()
    return row if 0 <= gap <= silence_threshold_seconds else None


def record_alert(
    conn: sqlite3.Connection,
    alert_id: str,
    host_name: str,
    timestamp: str,
    rule_id: str,
    rule_level: int | None,
    rule_description: str,
    source_type: str,
    key_fields: dict,
    micro_window_seconds: int,
    silence_threshold_seconds: int,
) -> tuple[str, str]:
    """Simpen 1 alert baru, join ke event (tier-1, micro-cluster multi-sensor) & incident
    (tier-2, full chain) yang sesuai. Gap dihitung dari timestamp alert vs last_seen event/
    incident TERAKHIR -- bukan dari waktu poll sekarang -- biar chain yang jeda antar-alertnya
    masih di bawah threshold tetep nyambung walau udah lewat beberapa poll cycle."""
    event = _find_open_event(conn, host_name, timestamp, micro_window_seconds)
    if event is None:
        event_id = str(uuid.uuid4())
        conn.execute(
            "INSERT INTO events (event_id, host_name, first_seen_ts, last_seen_ts, incident_id) "
            "VALUES (?, ?, ?, ?, NULL)",
            (event_id, host_name, timestamp, timestamp),
        )
    else:
        event_id = event["event_id"]
        conn.execute("UPDATE events SET last_seen_ts = ? WHERE event_id = ?", (timestamp, event_id))

    incident = _find_open_incident(conn, host_name, timestamp, silence_threshold_seconds)
    if incident is None:
        incident_id = str(uuid.uuid4())
        conn.execute(
            "INSERT INTO incidents (incident_id, host_name, status, first_seen_ts, last_seen_ts) "
            "VALUES (?, ?, 'open', ?, ?)",
            (incident_id, host_name, timestamp, timestamp),
        )
    else:
        incident_id = incident["incident_id"]
        conn.execute("UPDATE incidents SET last_seen_ts = ? WHERE incident_id = ?", (timestamp, incident_id))

    conn.execute("UPDATE events SET incident_id = ? WHERE event_id = ?", (incident_id, event_id))

    conn.execute(
        "INSERT INTO processed_alerts "
        "(alert_id, host_name, timestamp, rule_id, rule_level, rule_description, source_type, key_fields, event_id) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            alert_id, host_name, timestamp, rule_id, rule_level, rule_description,
            source_type, json.dumps(key_fields), event_id,
        ),
    )
    conn.commit()
    return event_id, incident_id


def get_incidents_ready_to_close(conn: sqlite3.Connection, silence_threshold_seconds: int) -> list[sqlite3.Row]:
    """Sweep penutupan -- dipanggil SETELAH semua alert baru di cycle ini selesai
    diproses (record_alert), biar incident_last_seen_ts udah ke-update duluan sebelum
    dievaluasi. Kalau dibalik urutannya, incident bisa keburu ditutup padahal alert
    lanjutannya ada di batch yang sama."""
    now = _now_iso()
    rows = conn.execute("SELECT * FROM incidents WHERE status = 'open'").fetchall()
    ready = []
    for row in rows:
        gap = (datetime.fromisoformat(now) - datetime.fromisoformat(row["last_seen_ts"])).total_seconds()
        if gap >= silence_threshold_seconds:
            ready.append(row)
    return ready


def get_incident_events(conn: sqlite3.Connection, incident_id: str) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM events WHERE incident_id = ? ORDER BY first_seen_ts ASC", (incident_id,)
    ).fetchall()


def get_event_alerts(conn: sqlite3.Connection, event_id: str) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM processed_alerts WHERE event_id = ? ORDER BY timestamp ASC", (event_id,)
    ).fetchall()


def close_incident(conn: sqlite3.Connection, incident_id: str):
    conn.execute(
        "UPDATE incidents SET status = 'closed', finalized_at = ? WHERE incident_id = ?",
        (_now_iso(), incident_id),
    )
    conn.commit()


def record_pending_exec(
    conn: sqlite3.Connection,
    alert_id: str,
    host_name: str,
    task_key: str | None,
    timestamp: str,
    rule_id: str,
    payload: dict,
):
    """Simpen alert eksekusi (Sysmon event 1) yang nunggu dipasangin alert korelasi
    dari decoder lain. Timestamp WAJIB sudah dinormalisasi ke UTC ISO sama pemanggil,
    karena pencarian pasangannya ngitung selisih detik antar dua alert."""
    conn.execute(
        "INSERT INTO pending_exec_alerts (alert_id, host_name, task_key, timestamp, rule_id, payload) "
        "VALUES (?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(alert_id) DO UPDATE SET "
        "host_name = excluded.host_name, task_key = excluded.task_key, "
        "timestamp = excluded.timestamp, rule_id = excluded.rule_id, payload = excluded.payload",
        (alert_id, host_name, task_key, timestamp, rule_id, json.dumps(payload)),
    )
    conn.commit()


def find_pending_exec_by_task(
    conn: sqlite3.Connection, host_name: str, task_key: str, alert_ts: str, window_seconds: int
) -> sqlite3.Row | None:
    rows = conn.execute(
        "SELECT * FROM pending_exec_alerts WHERE host_name = ? AND task_key = ? ORDER BY timestamp DESC",
        (host_name, task_key),
    ).fetchall()
    return _first_within_window(rows, alert_ts, window_seconds)


def find_latest_pending_exec(
    conn: sqlite3.Connection, host_name: str, alert_ts: str, window_seconds: int
) -> sqlite3.Row | None:
    rows = conn.execute(
        "SELECT * FROM pending_exec_alerts WHERE host_name = ? ORDER BY timestamp DESC",
        (host_name,),
    ).fetchall()
    return _first_within_window(rows, alert_ts, window_seconds)


def _first_within_window(rows: list[sqlite3.Row], alert_ts: str, window_seconds: int) -> sqlite3.Row | None:
    for row in rows:
        gap = (datetime.fromisoformat(alert_ts) - datetime.fromisoformat(row["timestamp"])).total_seconds()
        if 0 <= gap <= window_seconds:
            return row
    return None


def delete_pending_exec(conn: sqlite3.Connection, alert_id: str):
    conn.execute("DELETE FROM pending_exec_alerts WHERE alert_id = ?", (alert_id,))
    conn.commit()


def prune_pending_exec(conn: sqlite3.Connection, retention_seconds: int) -> int:
    """Buang alert eksekusi yang gak pernah kepasangin. Tanpa ini tabelnya numpuk dan
    fallback pencocokan per-host bisa narik alert basi dari jam-jam sebelumnya."""
    now = datetime.now(timezone.utc)
    deleted = 0
    for row in conn.execute("SELECT alert_id, timestamp FROM pending_exec_alerts").fetchall():
        if (now - datetime.fromisoformat(row["timestamp"])).total_seconds() > retention_seconds:
            conn.execute("DELETE FROM pending_exec_alerts WHERE alert_id = ?", (row["alert_id"],))
            deleted += 1
    if deleted:
        conn.commit()
    return deleted
