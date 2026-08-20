"""
api-service.py - SOC AI+RAG API (Fase 1 triage + Fase 2 korelasi), 1 service.

Awalnya Fase 1 (/triage) dan Fase 2 (/correlate/tick) dipisah jadi 2 proses/port
sendiri-sendiri -- di-gabung jadi 1 app karena dua-duanya jalan di M1 yang sama,
sama-sama numpang Ollama+ChromaDB (rag_common.py), dan gak ada alasan kuat buat
nambah operational overhead (2 port, 2 proses buat di-manage/di-restart) padahal
beda-nya cuma trigger (push per-alert dari n8n webhook vs pull terjadwal n8n
Schedule Trigger) -- itu cukup dibedain di level ROUTE, bukan level proses.

- POST /triage        -> Fase 1, dipanggil n8n tiap alert masuk (lihat triage()
                          di bawah, logic-nya tetap di file ini -- ringan, gak
                          butuh state).
- POST /correlate/tick -> Fase 2, dipanggil n8n Schedule Trigger tiap ~15 menit.
                          Logic (state SQLite, query Wazuh Indexer, clustering)
                          ada di correlation_logic.py, run_correlation_tick().

Retrieval RAG + Ollama client di-share dari rag_common.py buat kedua route.

Usage: uvicorn api-service:app --host 0.0.0.0 --port 8000
"""

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

import correlation_logic
import rag_common

GENERAL_RESULTS = 4
MITRE_RESULTS = 3

app = FastAPI(title="SOC AI+RAG Service")


def build_query_text(alert: dict) -> str:
    """Susun teks semantik dari alert buat di-embed jadi query retrieval."""
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
        parts.append(alert["enriched_summary"])

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
{alert.get('enriched_summary', 'n/a')}

=== KONTEKS DARI KNOWLEDGE BASE (Sigma/YARA/MITRE/CVE/THM) ===
{context}

=== TUGAS ===
Susun triage singkat dengan format ini:
1. **Ringkasan kejadian** — 2-3 kalimat, bahasa awam, apa yang kejadian ini sebenernya.
2. **Kaitan MITRE ATT&CK** — tactic/technique yang paling relevan (pakai konteks di atas kalau ada), jelasin singkat.
3. **Kemungkinan arah serangan selanjutnya** — berdasarkan tactic saat ini di kill-chain, fase apa yang biasanya menyusul (misal: kalau ini fase Execution, attacker biasanya lanjut ke Persistence/Privilege Escalation). Sebutkan tanda/log apa yang perlu dicek buat konfirmasi/deteksi fase lanjutannya.
4. **Catatan konfidensi** — kalau konteks di atas lemah/gak nyambung, sebutin di sini.
"""


@app.post("/triage")
async def triage(request: Request):
    alert = await request.json()

    try:
        context = rag_common.retrieve_context(build_query_text(alert), general_n=GENERAL_RESULTS, mitre_n=MITRE_RESULTS)
        prompt = build_prompt(alert, context)
        triage_text = rag_common.generate(prompt)

        # Balikin alert asli + triage jadi satu object flat, biar node n8n
        # setelah ini (Jira) gak perlu cross-reference ke node sebelumnya
        # buat akses rule/enriched_summary — semua field udah ada di sini.
        return JSONResponse({**alert, "triage": triage_text})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/correlate/tick")
async def correlate_tick():
    """Dipanggil n8n Schedule Trigger tiap SILENCE_THRESHOLD_MINUTES/2-an menit
    (disaranin 15 menit). 1 kali panggilan = 1 siklus penuh: tarik alert baru,
    update clustering, lalu finalize incident yang udah 'diem' >= silence threshold.
    n8n yang eksekusi Jira/Discord dari hasil finalized_incidents di response ini."""
    try:
        result = correlation_logic.run_correlation_tick()
        return JSONResponse(result)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/health")
async def health():
    return {"status": "ok", "collection_count": rag_common.collection.count()}
