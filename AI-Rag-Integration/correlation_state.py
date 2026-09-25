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
BUSY_TIMEOUT_MS = 5000

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

CREATE TABLE IF NOT EXISTS pending_cross_decoder_alerts (
    alert_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    host_name TEXT NOT NULL,
    task_key TEXT,
    timestamp TEXT NOT NULL,
    stored_at TEXT NOT NULL,
    rule_id TEXT,
    payload TEXT NOT NULL
);

DROP TABLE IF EXISTS pending_exec_alerts;
"""


def get_connection(db_path: str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    conn.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
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


def pair_or_store_cross_decoder(
    conn: sqlite3.Connection,
    alert_id: str,
    kind: str,
    counterpart_kind: str,
    host_name: str,
    task_key: str | None,
    timestamp: str,
    rule_id: str,
    payload: dict,
    window_seconds: int,
) -> tuple[sqlite3.Row | None, str | None]:
    """Cari pasangan lintas decoder; kalau belum ada, simpen alert ini buat nunggu.

    Dua alert yang dipasangin (Sysmon event 1 dan Security 4698) lahir dari event yang
    beda dan nyampe lewat eksekusi n8n yang beda, jadi urutan datengnya gak bisa
    diandelin -- terukur cuma 4 ms terpaut. Yang nentuin siapa nyimpen dan siapa narik
    itu siapa yang nyampe BELAKANGAN, bukan rule ID-nya.

    Seluruhnya jalan di dalam satu transaksi `BEGIN IMMEDIATE` karena cari-lalu-simpen
    itu read-modify-write: tanpa lock, dua alert yang nyampe barengan sama-sama gak
    nemu pasangan, sama-sama nyimpen, dan notifikasinya gak pernah kekirim sama sekali.
    Timestamp WAJIB sudah dinormalisasi ke UTC ISO sama pemanggil.
    """
    conn.execute("BEGIN IMMEDIATE")
    try:
        row, match_type = None, None
        if task_key:
            row = _first_within_window(
                conn.execute(
                    "SELECT * FROM pending_cross_decoder_alerts "
                    "WHERE kind = ? AND host_name = ? AND task_key = ? ORDER BY timestamp DESC",
                    (counterpart_kind, host_name, task_key),
                ).fetchall(),
                timestamp,
                window_seconds,
            )
            match_type = "task_name" if row else None
        if row is None:
            row = _first_within_window(
                conn.execute(
                    "SELECT * FROM pending_cross_decoder_alerts "
                    "WHERE kind = ? AND host_name = ? ORDER BY timestamp DESC",
                    (counterpart_kind, host_name),
                ).fetchall(),
                timestamp,
                window_seconds,
            )
            match_type = "host_window" if row else None

        if row is not None:
            conn.execute("DELETE FROM pending_cross_decoder_alerts WHERE alert_id = ?", (row["alert_id"],))
        else:
            conn.execute(
                "INSERT INTO pending_cross_decoder_alerts "
                "(alert_id, kind, host_name, task_key, timestamp, stored_at, rule_id, payload) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(alert_id) DO UPDATE SET "
                "kind = excluded.kind, host_name = excluded.host_name, task_key = excluded.task_key, "
                "timestamp = excluded.timestamp, stored_at = excluded.stored_at, "
                "rule_id = excluded.rule_id, payload = excluded.payload",
                (alert_id, kind, host_name, task_key, timestamp, _now_iso(), rule_id, json.dumps(payload)),
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return row, match_type


def _first_within_window(rows: list[sqlite3.Row], alert_ts: str, window_seconds: int) -> sqlite3.Row | None:
    """Arah waktunya sengaja gak dikunci (`abs`): dua alert yang dipasangin nunjuk instant
    yang sama -- terukur 4 ms terpaut, pernah 0 ms -- dan sisi mana yang timestamp-nya lebih
    tua bisa kebalik karena jitter urutan proses di analysisd. Yang nentuin pasangan itu
    kedekatan waktu, bukan urutannya."""
    for row in rows:
        gap = (datetime.fromisoformat(alert_ts) - datetime.fromisoformat(row["timestamp"])).total_seconds()
        if abs(gap) <= window_seconds:
            return row
    return None


def take_expired_pending(conn: sqlite3.Connection, kind: str, older_than_seconds: int) -> list[sqlite3.Row]:
    """Ambil sekaligus hapus alert `kind` yang nunggu pasangan lebih lama dari jendela
    korelasi. Umurnya diukur dari `stored_at` (kapan row masuk), bukan `timestamp` alert:
    agent yang abis reconnect nge-flush log lama sekaligus, jadi alert bisa nyampe dengan
    timestamp jam-jam sebelumnya dan bakal langsung dianggap kedaluwarsa sebelum
    pasangannya sempat dateng. Baca-lalu-hapus dikunci `BEGIN IMMEDIATE` biar dua pemanggil sweep yang
    kebetulan barengan gak ngeluarin alert yang sama dua kali."""
    now = datetime.now(timezone.utc)
    conn.execute("BEGIN IMMEDIATE")
    try:
        expired = [
            row
            for row in conn.execute(
                "SELECT * FROM pending_cross_decoder_alerts WHERE kind = ? ORDER BY timestamp ASC", (kind,)
            ).fetchall()
            if (now - datetime.fromisoformat(row["stored_at"])).total_seconds() > older_than_seconds
        ]
        for row in expired:
            conn.execute("DELETE FROM pending_cross_decoder_alerts WHERE alert_id = ?", (row["alert_id"],))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return expired


def prune_pending_cross_decoder(conn: sqlite3.Connection, retention_seconds: int) -> int:
    """Buang alert yang gak pernah kepasangin. Tanpa ini tabelnya numpuk dan fallback
    pencocokan per-host bisa narik alert basi dari jam-jam sebelumnya. Sama kayak
    `take_expired_pending`, umurnya dari `stored_at` -- `timestamp` alert dipakainya buat
    nentuin pasangan, bukan buat nentuin kapan nyerah nunggu."""
    now = datetime.now(timezone.utc)
    deleted = 0
    for row in conn.execute("SELECT alert_id, stored_at FROM pending_cross_decoder_alerts").fetchall():
        if (now - datetime.fromisoformat(row["stored_at"])).total_seconds() > retention_seconds:
            conn.execute("DELETE FROM pending_cross_decoder_alerts WHERE alert_id = ?", (row["alert_id"],))
            deleted += 1
    if deleted:
        conn.commit()
    return deleted
