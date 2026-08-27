import os
import subprocess

import chromadb
import ollama

CHROMA_PATH = os.environ.get("CHROMA_PATH", "./chroma_db")
COLLECTION_NAME = "soc_knowledge"
EMBED_MODEL = "nomic-embed-text"
GENERATE_MODEL = "llama3.2:3b"
MAX_CONTEXT_DOC_CHARS = 800

OLLAMA_HOST = os.environ.get("OLLAMA_HOST_URL", "http://127.0.0.1:11434")

CLAUDE_CLI_PATH = os.environ.get("CLAUDE_CLI_PATH", "claude")
CLAUDE_CLI_MODEL = os.environ.get("CLAUDE_CLI_MODEL", "sonnet")
CLAUDE_CLI_TIMEOUT_SECONDS = int(os.environ.get("CLAUDE_CLI_TIMEOUT_SECONDS", "120"))

GENERATE_OPTIONS = {
    "temperature": 0.2,
    "num_ctx": 8192,
    "seed": 42,
}

RETRIEVAL_ROLES = {
    "mitre_attack": {
        "label": "MITRE ATT&CK — Technique Classification (resmi)",
        "extra_where": {"object_type": {"$in": ["attack-pattern", "x-mitre-analytic", "x-mitre-detection-strategy"]}},
    },
    "sigma_rule": {"label": "Sigma Rules — Referensi Flow Serangan / Kemungkinan Next Step"},
    "yara_rule": {"label": "YARA Rules — Rekomendasi Deteksi Tambahan"},
    "cve_entry": {"label": "CVE — Kemungkinan Kerentanan yang Dieksploitasi"},
    "thm_writeup": {"label": "THM Writeup — Catatan/Evaluasi Konteks Tambahan"},
}

ollama_client = ollama.Client(host=OLLAMA_HOST)
chroma_client = chromadb.PersistentClient(path=CHROMA_PATH)
collection = chroma_client.get_collection(COLLECTION_NAME)


def embed_query(text: str) -> list[float]:
    response = ollama_client.embeddings(model=EMBED_MODEL, prompt=text)
    return response["embedding"]


def format_context_docs(results, label: str) -> list[str]:
    formatted = []
    docs = results.get("documents", [[]])[0]
    metadatas = results.get("metadatas", [[]])[0]

    for doc, meta in zip(docs, metadatas):
        doc_type = meta.get("type", label).upper()
        title = meta.get("title") or meta.get("name") or meta.get("rule_name") or meta.get("cve_id") or ""
        snippet = doc[:MAX_CONTEXT_DOC_CHARS]
        formatted.append(f"[{doc_type}] {title}\n{snippet}")

    return formatted


def retrieve_context(query_text: str, n_per_type: dict[str, int]) -> str:
    query_embedding = embed_query(query_text)

    blocks = []
    for doc_type, cfg in RETRIEVAL_ROLES.items():
        n = n_per_type.get(doc_type, 0)
        if n <= 0:
            continue

        where = {"type": doc_type}
        extra_where = cfg.get("extra_where")
        if extra_where:
            where = {"$and": [{"type": doc_type}, extra_where]}

        results = collection.query(query_embeddings=[query_embedding], n_results=n, where=where)
        docs = format_context_docs(results, doc_type)
        if docs:
            blocks.append(f"### {cfg['label']}\n\n" + "\n\n".join(docs))

    if not blocks:
        return "(Tidak ada konteks relevan ditemukan di knowledge base.)"

    return "\n\n---\n\n".join(blocks)


def generate(prompt: str) -> str:
    response = ollama_client.generate(model=GENERATE_MODEL, prompt=prompt, options=GENERATE_OPTIONS)
    return response["response"]


def generate_via_claude_cli(prompt: str) -> str:
    result = subprocess.run(
        [
            CLAUDE_CLI_PATH, "-p",
            "--output-format", "text",
            "--model", CLAUDE_CLI_MODEL,
            "--disallowedTools", "Bash,Edit,Write,NotebookEdit,WebFetch,WebSearch,Read",
        ],
        input=prompt,
        capture_output=True,
        text=True,
        timeout=CLAUDE_CLI_TIMEOUT_SECONDS,
    )
    if result.returncode != 0:
        raise RuntimeError(f"claude CLI exited {result.returncode}: {result.stderr.strip()}")
    return result.stdout.strip()
