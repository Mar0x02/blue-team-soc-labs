import os
from datetime import datetime, timedelta, timezone

import yaml
from opensearchpy import OpenSearch

import correlation_state as state
import rag_common

WAZUH_INDEXER_HOST = os.environ.get("WAZUH_INDEXER_HOST", "")
WAZUH_INDEXER_PORT = int(os.environ.get("WAZUH_INDEXER_PORT", "9200"))
WAZUH_INDEXER_USER = os.environ.get("WAZUH_INDEXER_USER", "admin")
WAZUH_INDEXER_PASSWORD = os.environ.get("WAZUH_INDEXER_PASSWORD", "")
WAZUH_INDEXER_VERIFY_SSL = os.environ.get("WAZUH_INDEXER_VERIFY_SSL", "false").lower() == "true"
WAZUH_ALERT_INDEX = os.environ.get("WAZUH_ALERT_INDEX", "wazuh-alerts-*")

IP_HOST_MAPPING_PATH = os.environ.get("IP_HOST_MAPPING_PATH", "./ip-host-mapping.yml")
CORRELATION_DB_PATH = os.environ.get("CORRELATION_DB_PATH", "./correlation_state.db")

MIN_RULE_LEVEL = int(os.environ.get("MIN_RULE_LEVEL", "7"))
INITIAL_LOOKBACK_MINUTES = int(os.environ.get("INITIAL_LOOKBACK_MINUTES", "60"))
OVERLAP_BUFFER_MINUTES = int(os.environ.get("OVERLAP_BUFFER_MINUTES", "2"))
MICRO_CLUSTER_WINDOW_SECONDS = int(os.environ.get("MICRO_CLUSTER_WINDOW_SECONDS", "10"))
SILENCE_THRESHOLD_MINUTES = int(os.environ.get("SILENCE_THRESHOLD_MINUTES", "30"))

MAX_ALERTS_PER_TICK = 500

CORRELATION_N_PER_TYPE = {"mitre_attack": 3, "sigma_rule": 3, "yara_rule": 3, "cve_entry": 3, "thm_writeup": 2}

NARRATIVE_BACKEND = os.environ.get("NARRATIVE_BACKEND", "claude_cli")

_opensearch_client: OpenSearch | None = None
_ip_host_map: dict | None = None


def get_opensearch_client() -> OpenSearch:
    global _opensearch_client
    if _opensearch_client is None:
        _opensearch_client = OpenSearch(
            hosts=[{"host": WAZUH_INDEXER_HOST, "port": WAZUH_INDEXER_PORT}],
            http_auth=(WAZUH_INDEXER_USER, WAZUH_INDEXER_PASSWORD),
            use_ssl=True,
            verify_certs=WAZUH_INDEXER_VERIFY_SSL,
        )
    return _opensearch_client


def get_ip_host_map() -> dict:
    global _ip_host_map
    if _ip_host_map is None:
        with open(IP_HOST_MAPPING_PATH) as f:
            data = yaml.safe_load(f) or {}
        _ip_host_map = {h["ip"]: h for h in data.get("hosts", [])}
    return _ip_host_map


def query_new_alerts(query_from: str, query_to: str) -> list[dict]:
    client = get_opensearch_client()
    body = {
        "size": MAX_ALERTS_PER_TICK,
        "sort": [{"timestamp": "asc"}],
        "query": {
            "bool": {
                "filter": [
                    {"range": {"timestamp": {"gte": query_from, "lte": query_to}}},
                    {"range": {"rule.level": {"gte": MIN_RULE_LEVEL}}},
                ]
            }
        },
    }
    resp = client.search(index=WAZUH_ALERT_INDEX, body=body)
    return [hit["_source"] for hit in resp["hits"]["hits"]]


def resolve_host(alert: dict) -> str | None:
    agent = alert.get("agent", {}) or {}
    agent_id = agent.get("id")
    agent_name = agent.get("name")

    if agent_id and agent_id != "000" and agent_name:
        return agent_name

    ip_map = get_ip_host_map()
    data = alert.get("data", {}) or {}
    for ip_field in ("src_ip", "dest_ip"):
        ip = data.get(ip_field)
        if ip and ip in ip_map:
            return ip_map[ip]["name"]

    return None


def derive_source_type(alert: dict) -> str:
    rule = alert.get("rule", {}) or {}
    groups = rule.get("groups", []) or []
    data = alert.get("data", {}) or {}

    if "ids" in groups or data.get("src_ip") or data.get("dest_ip"):
        return "suricata_nids"
    if "audit" in groups or data.get("audit"):
        return "auditd"
    if "syscheck" in groups or alert.get("syscheck"):
        return "wazuh_fim"
    return "wazuh_native"


def extract_key_fields(alert: dict, source_type: str) -> dict:
    data = alert.get("data", {}) or {}

    if source_type == "suricata_nids":
        return {
            "src_ip": data.get("src_ip"),
            "dest_ip": data.get("dest_ip"),
            "dest_port": data.get("dest_port"),
            "signature": (data.get("alert", {}) or {}).get("signature"),
        }
    if source_type == "auditd":
        audit = data.get("audit", {}) or {}
        execve = audit.get("execve", {}) or {}
        argv_keys = sorted((k for k in execve if k[:1] == "a" and k[1:].isdigit()), key=lambda k: int(k[1:]))
        command = " ".join(execve[k] for k in argv_keys) if argv_keys else audit.get("exe")
        return {"command": command}
    if source_type == "wazuh_fim":
        syscheck = alert.get("syscheck", {}) or {}
        return {"path": syscheck.get("path"), "event": syscheck.get("event")}
    return {}


def ingest_new_alerts() -> int:
    conn = state.get_connection(CORRELATION_DB_PATH)
    now = datetime.now(timezone.utc)
    checkpoint = state.get_checkpoint(conn)

    if checkpoint:
        query_from = (datetime.fromisoformat(checkpoint) - timedelta(minutes=OVERLAP_BUFFER_MINUTES)).isoformat()
    else:
        query_from = (now - timedelta(minutes=INITIAL_LOOKBACK_MINUTES)).isoformat()

    raw_alerts = query_new_alerts(query_from, now.isoformat())

    processed_count = 0
    latest_ts = checkpoint
    for alert in raw_alerts:
        alert_id = alert.get("id")
        timestamp = alert.get("timestamp")
        if not alert_id or not timestamp:
            continue
        if state.is_processed(conn, alert_id):
            continue

        host_name = resolve_host(alert)
        if host_name is None:
            continue

        rule = alert.get("rule", {}) or {}
        source_type = derive_source_type(alert)
        key_fields = extract_key_fields(alert, source_type)

        state.record_alert(
            conn,
            alert_id=alert_id,
            host_name=host_name,
            timestamp=timestamp,
            rule_id=str(rule.get("id", "")),
            rule_level=rule.get("level"),
            rule_description=rule.get("description", ""),
            source_type=source_type,
            key_fields=key_fields,
            micro_window_seconds=MICRO_CLUSTER_WINDOW_SECONDS,
            silence_threshold_seconds=SILENCE_THRESHOLD_MINUTES * 60,
        )
        processed_count += 1
        if latest_ts is None or timestamp > latest_ts:
            latest_ts = timestamp

    if latest_ts:
        state.set_checkpoint(conn, latest_ts)

    conn.close()
    return processed_count


def build_correlation_query_text(events_with_alerts: list[dict]) -> str:
    lines = []
    for event in events_with_alerts:
        for a in event["alerts"]:
            line = a["rule_description"]
            if a["key_fields"] and a["key_fields"] != "{}":
                line = f"{line} {a['key_fields']}"
            lines.append(line)
    unique_lines = list(dict.fromkeys(lines))
    return "\n".join(unique_lines) if unique_lines else "unknown multi-stage security incident"


def build_correlation_prompt(host_info: dict, events_with_alerts: list[dict], context: str) -> str:
    timeline_lines = []
    for idx, event in enumerate(events_with_alerts, start=1):
        sources = ", ".join(sorted({a["source_type"] for a in event["alerts"]}))
        timeline_lines.append(f"Event {idx} — {event['first_seen_ts']}")
        timeline_lines.append(f"  Source(s): {sources}")
        for alert in event["alerts"]:
            timeline_lines.append(
                f"  - rule.id: {alert['rule_id']} | level: {alert['rule_level']} | "
                f"{alert['rule_description']} | indikator: {alert['key_fields']}"
            )
    timeline_text = "\n".join(timeline_lines)

    return f"""Kamu adalah asisten SOC L1 yang menyusun kronologi insiden dari kumpulan alert
yang sudah dikelompokkan sistem korelasi berdasarkan host yang sama & rentang waktu berdekatan.
Jawab dalam Bahasa Indonesia (istilah teknis boleh tetap Bahasa Inggris).

ATURAN WAJIB:
- JANGAN pakai nomor rule Wazuh (contoh: 100300) sebagai MITRE technique ID -- itu ID internal
  sistem, BUKAN MITRE ID (format T####).
- Kalau gak yakin technique ID spesifik dari konteks RAG yang dikasih, cukup sebut nama TACTIC-nya
  aja (contoh: "Discovery", "Credential Access"), atau tulis eksplisit "tidak dapat dipastikan dari
  konteks yang tersedia". JANGAN memaksakan technique ID kalau gak yakin.
- JANGAN mengarang hubungan antar-event yang gak didukung data eksplisit di bawah. Kalau
  pengelompokan ini keliatan gak koheren (event yang gak nyambung ceritanya), sebutkan itu
  secara eksplisit -- jangan dipaksain jadi 1 cerita utuh.
- Event yang punya >1 source (misal auditd + Suricata) itu 1 AKSI NYATA yang dikonfirmasi 2 sensor
  beda -- jelasin per-layer (network vs host), JANGAN dihitung jadi 2 langkah terpisah.
- Alert-alert DALAM 1 Event yang sama adalah proses-proses BERBEDA yang tercatat nyaris bersamaan
  (window waktu sangat singkat) di host yang sama -- kemungkinan besar bagian dari SATU rangkaian
  eksekusi command yang sama (misal di-chain lewat `;`/`&&` dalam satu request), BUKAN aksi
  independen yang gak berhubungan. ini fakta struktural dari cara alert dikelompokkan, BUKAN
  kesimpulan keamanan -- kesimpulan soal berbahaya/tidaknya tetap kamu yang nentuin dari data.

=== KONTEKS HOST ===
Host: {host_info.get('name', 'n/a')} ({host_info.get('ip', 'n/a')}, zona {host_info.get('zone', 'n/a')}, role {host_info.get('role', 'n/a')})

=== TIMELINE EVENT (berurutan) ===
{timeline_text}

=== KONTEKS DARI KNOWLEDGE BASE ===
Konteks di bawah datang dari sumber yang beda-beda, masing-masing peran beda -- JANGAN dicampur:
- MITRE ATT&CK: satu-satunya sumber buat tactic/technique ID per event (bagian 2 di bawah).
  Kalau blok ini kosong/gak match buat suatu event, ikuti aturan "jangan paksain technique ID"
  di atas -- cukup sebut tactic-nya aja atau bilang gak yakin.
- Sigma Rules: dipakai buat menduga KEMUNGKINAN ARAH SERANGAN LANJUTAN (bagian 3) -- pattern
  deteksi di Sigma sering merepresentasikan fase serangan yang berdekatan/berikutnya dari
  chain yang udah kejadian, bukan buat classification event yang udah ada di timeline.
- YARA Rules: kalau ada yang relevan, sebutkan sebagai REKOMENDASI deteksi konkret di bagian 4.
- CVE: sebutkan di bagian 4 kalau ada kerentanan spesifik yang match sama pola serangan di
  chain ini (endpoint/service yang disebut di alert).
- THM Writeup: referensi/evaluasi tambahan, bobot PALING RENDAH -- jangan jadi dasar utama
  kesimpulan manapun.

{context}

=== OUTPUT YANG DIMINTA ===
1. **Ringkasan kronologis** — naratif singkat per event, berurutan.
2. **Klasifikasi tactic MITRE per event** — bukan technique ID kecuali yakin (dari blok MITRE ATT&CK), sertakan catatan confidence.
3. **Kesimpulan arah serangan keseluruhan** — sejauh mana chain ini berkembang (recon doang? sampai initial access? sampai privesc/exfiltrasi?), plus kemungkinan next step (pakai blok Sigma Rules kalau ada yang relevan).
4. **Rekomendasi tindak lanjut** buat analyst — sebutkan YARA rule yang relevan (kalau ada) buat rekomendasi deteksi, dan CVE yang match (kalau ada) buat kemungkinan kerentanan yang dieksploitasi.
5. **Catatan confidence keseluruhan** — transparan soal keterbatasan data/retrieval.
"""


def finalize_incident(conn, incident_row, host_map_by_name: dict) -> dict:
    events = state.get_incident_events(conn, incident_row["incident_id"])
    events_with_alerts = []
    all_alert_ids = []
    for event in events:
        alerts = state.get_event_alerts(conn, event["event_id"])
        alert_dicts = []
        for a in alerts:
            alert_dicts.append(
                {
                    "alert_id": a["alert_id"],
                    "rule_id": a["rule_id"],
                    "rule_level": a["rule_level"],
                    "rule_description": a["rule_description"],
                    "source_type": a["source_type"],
                    "key_fields": a["key_fields"],
                }
            )
            all_alert_ids.append(a["alert_id"])
        events_with_alerts.append({"first_seen_ts": event["first_seen_ts"], "alerts": alert_dicts})

    host_info = host_map_by_name.get(incident_row["host_name"], {"name": incident_row["host_name"]})

    query_text = build_correlation_query_text(events_with_alerts)
    context = rag_common.retrieve_context(query_text, CORRELATION_N_PER_TYPE)
    prompt = build_correlation_prompt(host_info, events_with_alerts, context)
    if NARRATIVE_BACKEND == "claude_cli":
        narrative = rag_common.generate_via_claude_cli(prompt)
    else:
        narrative = rag_common.generate(prompt)

    state.close_incident(conn, incident_row["incident_id"])

    return {
        "incident_id": incident_row["incident_id"],
        "host_name": incident_row["host_name"],
        "narrative": narrative,
        "alert_ids": all_alert_ids,
    }


def run_correlation_tick() -> dict:
    new_count = ingest_new_alerts()

    conn = state.get_connection(CORRELATION_DB_PATH)
    ip_map = get_ip_host_map()
    host_map_by_name = {h["name"]: h for h in ip_map.values()}

    ready = state.get_incidents_ready_to_close(conn, SILENCE_THRESHOLD_MINUTES * 60)
    finalized = [finalize_incident(conn, incident, host_map_by_name) for incident in ready]

    conn.close()
    return {"new_alerts_processed": new_count, "finalized_incidents": finalized}
