"""
triage-pipeline.py - AI Triage Endpoint (Fase 1: triage + arah serangan)
Serve API lokal di M1 yang dipanggil n8n (POST /triage) buat ngehasilin ringkasan
triage dari alert Wazuh yang udah di-enrich, pakai konteks dari ChromaDB (soc_knowledge).

Usage: uvicorn triage-pipeline:app --host 0.0.0.0 --port 8000
"""

import chromadb
import ollama
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

# ============ CONFIG ============
CHROMA_PATH = "./chroma_db"
COLLECTION_NAME = "soc_knowledge"
EMBED_MODEL = "nomic-embed-text"
GENERATE_MODEL = "llama3.2:3b"
GENERAL_RESULTS = 4
MITRE_RESULTS = 3
MAX_CONTEXT_DOC_CHARS = 800  # potong tiap dokumen context biar prompt gak membengkak

# Sampling options buat generate() — default Ollama gak cocok buat task factual kayak triage
GENERATE_OPTIONS = {
    "temperature": 0.2,  # rendah = konsisten/faktual, bukan variatif (default Ollama ~0.8, kekreatif buat ini)
    "num_ctx": 8192,     # context window — default Ollama sering 2048, bisa motong konteks RAG diam-diam kalau gak di-set
    "seed": 42,          # reproducible — alert yang sama persis harusnya hasil triage-nya konsisten
}
# ================================

ollama_client = ollama.Client(host="http://127.0.0.1:11434")
chroma_client = chromadb.PersistentClient(path=CHROMA_PATH)
collection = chroma_client.get_collection(COLLECTION_NAME)

app = FastAPI(title="SOC Triage Pipeline")


def embed_query(text: str) -> list[float]:
    response = ollama_client.embeddings(model=EMBED_MODEL, prompt=text)
    return response["embedding"]


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


def format_context_docs(results, label: str) -> list[str]:
    """Format hasil query ChromaDB jadi potongan teks berlabel buat prompt."""
    formatted = []
    docs = results.get("documents", [[]])[0]
    metadatas = results.get("metadatas", [[]])[0]

    for doc, meta in zip(docs, metadatas):
        doc_type = meta.get("type", label).upper()
        title = meta.get("title") or meta.get("name") or meta.get("rule_name") or meta.get("cve_id") or ""
        snippet = doc[:MAX_CONTEXT_DOC_CHARS]
        formatted.append(f"[{doc_type}] {title}\n{snippet}")

    return formatted


def retrieve_context(alert: dict) -> str:
    query_text = build_query_text(alert)
    query_embedding = embed_query(query_text)

    general_results = collection.query(
        query_embeddings=[query_embedding],
        n_results=GENERAL_RESULTS,
    )
    mitre_results = collection.query(
        query_embeddings=[query_embedding],
        n_results=MITRE_RESULTS,
        where={"type": "mitre_attack"},
    )

    context_chunks = format_context_docs(general_results, "general") + format_context_docs(mitre_results, "mitre_attack")

    if not context_chunks:
        return "(Tidak ada konteks relevan ditemukan di knowledge base.)"

    return "\n\n---\n\n".join(context_chunks)


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
        context = retrieve_context(alert)
        prompt = build_prompt(alert, context)

        response = ollama_client.generate(model=GENERATE_MODEL, prompt=prompt, options=GENERATE_OPTIONS)
        triage_text = response["response"]

        # Balikin alert asli + triage jadi satu object flat, biar node n8n
        # setelah ini (Jira) gak perlu cross-reference ke node sebelumnya
        # buat akses rule/enriched_summary — semua field udah ada di sini.
        return JSONResponse({**alert, "triage": triage_text})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/health")
async def health():
    return {"status": "ok", "collection_count": collection.count()}
