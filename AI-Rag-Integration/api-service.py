from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).parent / ".env")

import asyncio
import json
import os
import re
from datetime import datetime, timezone

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

import correlation_logic
import correlation_state as state
import rag_common

TRIAGE_N_PER_TYPE = {"mitre_attack": 2, "sigma_rule": 2, "yara_rule": 2, "cve_entry": 2, "thm_writeup": 1}

PROMPT_SUMMARY_MAX_CHARS = int(os.environ.get("TRIAGE_SUMMARY_MAX_CHARS", "4000"))
QUERY_SUMMARY_MAX_CHARS = int(os.environ.get("TRIAGE_QUERY_SUMMARY_MAX_CHARS", "1200"))

EXEC_RULE_IDS = {r.strip() for r in os.environ.get("CROSS_DECODER_EXEC_RULE_IDS", "100605").split(",") if r.strip()}
CORR_RULE_IDS = {r.strip() for r in os.environ.get("CROSS_DECODER_CORR_RULE_IDS", "100604").split(",") if r.strip()}
CROSS_DECODER_WINDOW_SECONDS = int(os.environ.get("CROSS_DECODER_WINDOW_SECONDS", "300"))
CROSS_DECODER_RETENTION_SECONDS = int(os.environ.get("CROSS_DECODER_RETENTION_SECONDS", "1800"))
CROSS_DECODER_LOOKUP_RETRIES = int(os.environ.get("CROSS_DECODER_LOOKUP_RETRIES", "3"))
CROSS_DECODER_LOOKUP_RETRY_DELAY = float(os.environ.get("CROSS_DECODER_LOOKUP_RETRY_DELAY", "0.5"))
COMMAND_LINE_MAX_CHARS = 800
DISCORD_MESSAGE_MAX_CHARS = int(os.environ.get("DISCORD_MESSAGE_MAX_CHARS", "1900"))

TASK_NAME_RE = re.compile(
    r"""[/-]tn\s+(?:\\?["'](?P<quoted>[^"'\\]+)\\?["']|(?P<bare>\S+))""",
    re.IGNORECASE,
)

app = FastAPI(title="SOC AI+RAG Service")


def clip(text: str | None, limit: int) -> str:
    if not text:
        return ""
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n[...dipotong, total {len(text)} karakter]"


def build_query_text(alert: dict) -> str:
    rule = alert.get("rule", {}) or {}
    parts = []

    if rule.get("description"):
        parts.append(rule["description"])

    mitre = rule.get("mitre", {}) or {}
    if mitre.get("technique"):
        parts.append("MITRE Technique: " + ", ".join(mitre["technique"]))
    if mitre.get("tactic"):
        parts.append("MITRE Tactic: " + ", ".join(mitre["tactic"]))
    if mitre.get("id"):
        parts.append("MITRE ID: " + ", ".join(mitre["id"]))

    if alert.get("enriched_summary"):
        parts.append(clip(alert["enriched_summary"], QUERY_SUMMARY_MAX_CHARS))

    return "\n".join(parts) if parts else "unknown security alert"


def build_prompt(alert: dict, context: str) -> str:
    rule = alert.get("rule", {}) or {}
    agent = alert.get("agent", {}) or {}

    return f"""Kamu adalah asisten SOC L1 yang bantu triage alert dari Wazuh. Jawab dalam Bahasa Indonesia
(istilah teknis boleh tetap Bahasa Inggris). Jangan mengarang fakta — kalau konteks di bawah gak relevan
atau gak cukup buat menjawab bagian tertentu, bilang terus terang, jangan dipaksain.

=== ALERT ===
Rule: {rule.get('description', 'n/a')}
Level: {rule.get('level', 'n/a')} | Rule ID: {rule.get('id', 'n/a')}
Agent: {agent.get('name', 'n/a')}
Detail tambahan:
{clip(alert.get('enriched_summary'), PROMPT_SUMMARY_MAX_CHARS) or 'n/a'}

=== KONTEKS DARI KNOWLEDGE BASE ===
Konteks di bawah datang dari sumber yang beda-beda, masing-masing peran beda -- JANGAN dicampur:
- MITRE ATT&CK: satu-satunya sumber buat tactic/technique ID. Kalau blok ini kosong atau
  gak match, jangan paksain technique ID, cukup sebut tactic-nya aja atau bilang gak yakin.
- Sigma Rules: dipakai buat menduga KEMUNGKINAN ARAH SERANGAN LANJUTAN (bagian 3 di bawah),
  bukan buat classification alert yang lagi ditriage sekarang -- pattern deteksi di Sigma
  sering merepresentasikan fase serangan yang berdekatan/berikutnya.
- YARA Rules: kalau ada yang relevan, sebutkan sebagai rekomendasi deteksi konkret.
- CVE: sebutkan kalau ada kerentanan spesifik yang match sama pola alert ini.
- THM Writeup: referensi/evaluasi tambahan, bobot paling rendah -- jangan jadi dasar
  utama kesimpulan.

{context}

=== TUGAS ===
Susun triage singkat dengan format ini:
1. **Ringkasan kejadian** — 2-3 kalimat, bahasa awam, apa yang kejadian ini sebenernya.
2. **Kaitan MITRE ATT&CK** — tactic/technique yang paling relevan (dari blok MITRE ATT&CK di atas kalau ada), jelasin singkat.
3. **Kemungkinan arah serangan selanjutnya** — berdasarkan tactic saat ini di kill-chain, fase apa yang biasanya menyusul (pakai blok Sigma Rules kalau ada yang relevan). Sebutkan tanda/log apa yang perlu dicek buat konfirmasi/deteksi fase lanjutannya.
4. **Rekomendasi deteksi & kerentanan terkait** — sebutkan YARA rule yang relevan (kalau ada) buat rekomendasi deteksi, dan CVE yang match (kalau ada) buat kemungkinan kerentanan yang dieksploitasi.
5. **Catatan konfidensi** — kalau konteks di atas lemah/gak nyambung, sebutin di sini.
"""


@app.post("/triage")
async def triage(request: Request):
    alert = await request.json()

    try:
        context = rag_common.retrieve_context(build_query_text(alert), TRIAGE_N_PER_TYPE)
        prompt = build_prompt(alert, context)
        triage_text = rag_common.generate(prompt)

        return JSONResponse({**alert, "triage": triage_text})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/correlate/tick")
async def correlate_tick():
    try:
        result = correlation_logic.run_correlation_tick()
        return JSONResponse(result)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)



def _eventdata(alert: dict) -> dict:
    """Wazuh ngirim field eventchannel di `data.win.eventdata`, tapi node n8n yang
    nge-flatten alert bisa naikin `win` ke top-level. Dua-duanya diterima biar route ini
    gak peduli dia dipanggil dari cabang n8n yang mana."""
    for base in (alert.get("data") or {}, alert):
        win = base.get("win") or {}
        if win.get("eventdata"):
            return win["eventdata"]
    return {}


def _parse_ts_utc(value: str | None) -> str:
    try:
        return datetime.fromisoformat(value).astimezone(timezone.utc).isoformat()
    except (TypeError, ValueError):
        return datetime.now(timezone.utc).isoformat()


def _normalize_task_key(name: str | None) -> str | None:
    """Nama task dari Sysmon (`/tn`) dan dari Security 4698 (`taskName`) nunjuk hal yang
    sama tapi bentuknya beda: 4698 ngasih path berawalan backslash, dan penamaan task di
    Windows gak case-sensitive."""
    if not name:
        return None
    cleaned = name.strip().strip('"\'').lstrip("\\")
    return cleaned.casefold() or None


def _task_name_from_command_line(command_line: str | None) -> str | None:
    if not command_line:
        return None
    match = TASK_NAME_RE.search(command_line)
    if not match:
        return None
    return match.group("quoted") or match.group("bare")


def _task_key_from_command_line(command_line: str | None) -> str | None:
    return _normalize_task_key(_task_name_from_command_line(command_line))


def _exec_payload(alert: dict, eventdata: dict) -> dict:
    rule = alert.get("rule", {}) or {}
    command_line = eventdata.get("commandLine")
    return {
        "rule_id": str(rule.get("id", "")),
        "rule_description": rule.get("description"),
        "timestamp": alert.get("timestamp"),
        "command_line": command_line,
        "image": eventdata.get("image"),
        "parent_image": eventdata.get("parentImage"),
        "process_guid": eventdata.get("processGuid"),
        "user": eventdata.get("user"),
        "task_name": _task_name_from_command_line(command_line),
    }


def _build_notification(alert: dict, exec_payload: dict | None, match_type: str | None) -> str:
    rule = alert.get("rule", {}) or {}
    agent = alert.get("agent", {}) or {}
    eventdata = _eventdata(alert)
    task_name = (exec_payload or {}).get("task_name") or eventdata.get("taskName") or "n/a"

    lines = [
        f"\U0001f6a8 **{rule.get('description', 'Cross-decoder correlation')}**",
        f"Host: `{agent.get('name', 'n/a')}` | Rule: `{rule.get('id', 'n/a')}` (level {rule.get('level', 'n/a')})",
        f"Task: `{task_name}`",
        f"Waktu: {alert.get('timestamp', 'n/a')}",
    ]

    if exec_payload:
        command_line = (exec_payload.get("command_line") or "n/a")[:COMMAND_LINE_MAX_CHARS]
        lines += [
            "",
            f"Dari alert eksekusi `{exec_payload.get('rule_id', 'n/a')}` ({exec_payload.get('timestamp', 'n/a')}):",
            f"Parent: `{exec_payload.get('parent_image', 'n/a')}`",
            f"User: `{exec_payload.get('user', 'n/a')}`",
            f"Command: ```{command_line}```",
        ]
        if match_type == "host_window":
            lines.append(
                "\u26a0\ufe0f Dipasangin lewat host + jendela waktu, BUKAN nama task \u2014 "
                "konteks di atas belum tentu punya task yang sama."
            )
    else:
        lines += [
            "",
            f"\u26a0\ufe0f Alert eksekusi pasangannya gak ketemu dalam {CROSS_DECODER_WINDOW_SECONDS} detik terakhir. "
            "Command line task-nya gak tersedia \u2014 cek langsung di Wazuh.",
        ]

    return clip("\n".join(lines), DISCORD_MESSAGE_MAX_CHARS)


@app.post("/notify/cross-decoder")
async def notify_cross_decoder(request: Request):
    """Pasangin alert korelasi lintas decoder sama alert eksekusi yang mendahuluinya.

    Alert korelasi dipicu event dari decoder lain (Security 4698), jadi dia gak bawa field
    Sysmon yang isinya payload task. Route ini yang nyatuin: alert eksekusi disimpan dulu,
    alert korelasi datang belakangan dan narik konteksnya. Pengikatannya pakai nama task,
    yang di dua alert itu namanya beda field -- sesuatu yang `same_field` di Wazuh gak bisa.
    """
    alert = await request.json()
    rule = alert.get("rule", {}) or {}
    rule_id = str(rule.get("id", ""))
    host_name = (alert.get("agent", {}) or {}).get("name", "")
    timestamp = _parse_ts_utc(alert.get("timestamp"))
    eventdata = _eventdata(alert)

    try:
        if rule_id in EXEC_RULE_IDS:
            payload = _exec_payload(alert, eventdata)
            task_key = _task_key_from_command_line(eventdata.get("commandLine"))
            conn = state.get_connection(correlation_logic.CORRELATION_DB_PATH)
            try:
                state.record_pending_exec(
                    conn,
                    alert_id=str(alert.get("id", "")) or f"{host_name}:{timestamp}",
                    host_name=host_name,
                    task_key=task_key,
                    timestamp=timestamp,
                    rule_id=rule_id,
                    payload=payload,
                )
                pruned = state.prune_pending_exec(conn, CROSS_DECODER_RETENTION_SECONDS)
            finally:
                conn.close()
            return JSONResponse(
                {"action": "stored", "notify": False, "rule_id": rule_id, "task_key": task_key, "pruned": pruned}
            )

        if rule_id in CORR_RULE_IDS:
            task_key = _normalize_task_key(eventdata.get("taskName"))
            row = None
            match_type = None

            for attempt in range(CROSS_DECODER_LOOKUP_RETRIES):
                conn = state.get_connection(correlation_logic.CORRELATION_DB_PATH)
                try:
                    if task_key:
                        row = state.find_pending_exec_by_task(
                            conn, host_name, task_key, timestamp, CROSS_DECODER_WINDOW_SECONDS
                        )
                        match_type = "task_name" if row else None
                    if row is None:
                        row = state.find_latest_pending_exec(
                            conn, host_name, timestamp, CROSS_DECODER_WINDOW_SECONDS
                        )
                        match_type = "host_window" if row else None
                    if row is not None:
                        state.delete_pending_exec(conn, row["alert_id"])
                finally:
                    conn.close()
                if row is not None or attempt == CROSS_DECODER_LOOKUP_RETRIES - 1:
                    break
                await asyncio.sleep(CROSS_DECODER_LOOKUP_RETRY_DELAY)

            exec_payload = json.loads(row["payload"]) if row is not None else None
            return JSONResponse(
                {
                    "action": "notify",
                    "notify": True,
                    "matched": row is not None,
                    "match_type": match_type,
                    "rule_id": rule_id,
                    "host_name": host_name,
                    "task_key": task_key,
                    "exec_alert": exec_payload,
                    "message": _build_notification(alert, exec_payload, match_type),
                }
            )

        return JSONResponse({"action": "ignored", "notify": False, "rule_id": rule_id})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/health")
async def health():
    return {"status": "ok", "collection_count": rag_common.collection.count()}
