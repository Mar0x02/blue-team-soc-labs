from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

import correlation_logic
import rag_common

TRIAGE_N_PER_TYPE = {"mitre_attack": 2, "sigma_rule": 2, "yara_rule": 2, "cve_entry": 2, "thm_writeup": 1}

app = FastAPI(title="SOC AI+RAG Service")


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


@app.get("/health")
async def health():
    return {"status": "ok", "collection_count": rag_common.collection.count()}
