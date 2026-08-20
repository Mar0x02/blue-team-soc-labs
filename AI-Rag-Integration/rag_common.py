"""
rag_common.py - Shared RAG retrieval & Ollama client setup, dipakai bareng oleh
route /triage (Fase 1) dan correlation_logic.py (Fase 2) di api-service.py, biar
retrieval logic + config model gak dobel-tulis di 2 tempat.
"""

import os

import chromadb
import ollama

# ============ CONFIG ============
CHROMA_PATH = os.environ.get("CHROMA_PATH", "./chroma_db")
COLLECTION_NAME = "soc_knowledge"
EMBED_MODEL = "nomic-embed-text"
GENERATE_MODEL = "llama3.2:3b"
MAX_CONTEXT_DOC_CHARS = 800  # potong tiap dokumen context biar prompt gak membengkak

OLLAMA_HOST = os.environ.get("OLLAMA_HOST_URL", "http://127.0.0.1:11434")

# Sampling options buat generate() — default Ollama gak cocok buat task factual kayak triage/korelasi
GENERATE_OPTIONS = {
    "temperature": 0.2,  # rendah = konsisten/faktual, bukan variatif (default Ollama ~0.8, kekreatif buat ini)
    "num_ctx": 8192,     # context window — default Ollama sering 2048, bisa motong konteks RAG diam-diam
    "seed": 42,          # reproducible — input yang sama persis harusnya hasil generate-nya konsisten
}
# ================================

ollama_client = ollama.Client(host=OLLAMA_HOST)
chroma_client = chromadb.PersistentClient(path=CHROMA_PATH)
collection = chroma_client.get_collection(COLLECTION_NAME)


def embed_query(text: str) -> list[float]:
    response = ollama_client.embeddings(model=EMBED_MODEL, prompt=text)
    return response["embedding"]


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


def retrieve_context(query_text: str, general_n: int = 4, mitre_n: int = 3) -> str:
    """Retrieval umum (semua tipe) + retrieval khusus type: mitre_attack, digabung
    jadi 1 blok konteks. query_text disusun beda-beda oleh caller (route /triage
    dari 1 alert, correlation_logic.py dari beberapa event sekaligus)."""
    query_embedding = embed_query(query_text)

    general_results = collection.query(
        query_embeddings=[query_embedding],
        n_results=general_n,
    )
    mitre_results = collection.query(
        query_embeddings=[query_embedding],
        n_results=mitre_n,
        where={"type": "mitre_attack"},
    )

    context_chunks = format_context_docs(general_results, "general") + format_context_docs(mitre_results, "mitre_attack")

    if not context_chunks:
        return "(Tidak ada konteks relevan ditemukan di knowledge base.)"

    return "\n\n---\n\n".join(context_chunks)


def generate(prompt: str) -> str:
    response = ollama_client.generate(model=GENERATE_MODEL, prompt=prompt, options=GENERATE_OPTIONS)
    return response["response"]
