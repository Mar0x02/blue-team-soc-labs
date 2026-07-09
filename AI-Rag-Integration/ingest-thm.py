"""
ingest-thm.py - Load dokumen Markdown/PDF dan simpan ke ChromaDB
Usage: python ingest-thm.py --docs /path/to/docs
"""

import os
import sys
import argparse
import hashlib
import time
import chromadb
import ollama
from datetime import datetime

# Config
CHROMA_PATH = "./chroma_db"
COLLECTION_NAME = "soc_knowledge"
EMBED_MODEL = "nomic-embed-text"
CHUNK_SIZE = 1500
CHUNK_OVERLAP = 150
BATCH_SIZE = 50
ERROR_LOG_FILE = "./ingest_thm_errors.log"
MAX_EMBED_CHARS = 8000  # nomic-embed-text context = 8192 tokens, BERT tokenizer ~3-4 chars/token
EMBED_RETRIES = 3
EMBED_RETRY_DELAY = 5

ollama_client = ollama.Client(host='http://localhost:11434')
failed_files = []

def format_size(size_bytes):
    if size_bytes < 1024:
        return f"{size_bytes}B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes/1024:.1f}KB"
    else:
        return f"{size_bytes/(1024*1024):.1f}MB"

def chunk_text(text, chunk_size=CHUNK_SIZE, overlap=CHUNK_OVERLAP):
    """Split teks jadi chunks kecil"""
    chunks = []
    start = 0
    while start < len(text):
        end = start + chunk_size
        chunk = text[start:end]
        chunks.append(chunk)
        start += chunk_size - overlap
    return chunks

def embed_text(text):
    """Convert teks ke vector menggunakan Ollama dengan retry untuk transient error"""
    for attempt in range(1, EMBED_RETRIES + 1):
        try:
            response = ollama_client.embeddings(model=EMBED_MODEL, prompt=text[:MAX_EMBED_CHARS])
            return response["embedding"]
        except Exception as e:
            if attempt < EMBED_RETRIES:
                time.sleep(EMBED_RETRY_DELAY)
            else:
                raise

def load_document(filepath):
    """Load dokumen dari file (MD, TXT, PDF)"""
    ext = os.path.splitext(filepath)[1].lower()

    if ext in [".txt", ".md"]:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()

    elif ext == ".pdf":
        try:
            import pypdf
            reader = pypdf.PdfReader(filepath)
            text = ""
            for page in reader.pages:
                text += page.extract_text() + "\n"
            return text
        except Exception as e:
            raise Exception(f"Gagal baca PDF: {e}")

    return ""

def generate_unique_id(filepath, chunk_idx):
    key = f"{os.path.abspath(filepath)}__{chunk_idx}"
    return hashlib.md5(key.encode("utf-8")).hexdigest()

def ingest_folder(docs_path):
    client = chromadb.PersistentClient(path=CHROMA_PATH)
    try:
        collection = client.get_collection(COLLECTION_NAME)
        print(f"📂 Collection '{COLLECTION_NAME}' ditemukan.")
    except:
        collection = client.create_collection(COLLECTION_NAME)
        print(f"✨ Collection '{COLLECTION_NAME}' dibuat baru.")

    print("🔍 Checking existing docs di database...")
    existing_ids = set()
    offset = 0
    while True:
        batch = collection.get(limit=5000, offset=offset, include=[])
        if not batch['ids']:
            break
        existing_ids.update(batch['ids'])
        if len(batch['ids']) < 5000:
            break
        offset += 5000
    print(f"✅ Found {len(existing_ids)} chunks yang udah ada. Akan skip yang duplikat.\n")

    all_files = []
    for root, _, files in os.walk(docs_path):
        for filename in files:
            ext = os.path.splitext(filename)[1].lower()
            if ext in [".txt", ".md", ".pdf"]:
                all_files.append(os.path.join(root, filename))

    total_files = len(all_files)
    print(f"🔍 Ditemukan {total_files} file (MD/TXT/PDF).")
    print(f"⚡ Model: {EMBED_MODEL}")
    print(f"🚀 Mulai proses...\n")

    batch_ids, batch_embeddings, batch_documents, batch_metadatas = [], [], [], []
    total_chunks = 0
    skipped_existing = 0
    total_bytes_processed = 0
    start_time = time.time()

    for idx, filepath in enumerate(all_files, 1):
        filename = os.path.basename(filepath)
        file_size = os.path.getsize(filepath)
        size_str = format_size(file_size)

        sys.stdout.write(f"\r🔄 [{idx}/{total_files}] {filename} ({size_str}) | Reading...")
        sys.stdout.flush()

        if idx % 50 == 0 or idx == total_files:
            elapsed = time.time() - start_time
            rate = idx / elapsed if elapsed > 0 else 0
            eta = (total_files - idx) / rate if rate > 0 else 0
            sys.stdout.write(
                f"\n  📊 Progress: {idx}/{total_files} ({idx*100//total_files}%) | "
                f"Chunks: {total_chunks} | Skipped: {skipped_existing} | "
                f"Failed: {len(failed_files)} | "
                f"Processed: {format_size(total_bytes_processed)} | "
                f"ETA: {eta//60:.0f}m{eta%60:.0f}s\n"
            )
            sys.stdout.flush()

        try:
            text = load_document(filepath)

            if not text.strip():
                sys.stdout.write(f"\r⏭️  [{idx}/{total_files}] {filename} ({size_str}) | Skipped (kosong)\n")
                sys.stdout.flush()
                continue

            chunks = chunk_text(text)
            file_chunks_added = 0

            for i, chunk in enumerate(chunks):
                if not chunk.strip():
                    continue

                sys.stdout.write(f"\r🔄 [{idx}/{total_files}] {filename} ({size_str}) | Chunk {i+1}/{len(chunks)}")
                sys.stdout.flush()

                doc_id = generate_unique_id(filepath, i)
                if doc_id in existing_ids:
                    skipped_existing += 1
                    continue

                try:
                    embedding = embed_text(chunk)
                except Exception as e:
                    failed_files.append({"path": filepath, "chunk": i, "reason": f"Embed: {str(e)[:80]}"})
                    continue

                batch_ids.append(doc_id)
                batch_embeddings.append(embedding)
                batch_documents.append(chunk)
                batch_metadatas.append({"source": filename, "chunk": i, "type": "thm_writeup"})
                total_chunks += 1
                file_chunks_added += 1

                if len(batch_ids) >= BATCH_SIZE:
                    collection.upsert(
                        ids=batch_ids, embeddings=batch_embeddings,
                        documents=batch_documents, metadatas=batch_metadatas
                    )
                    batch_ids.clear(); batch_embeddings.clear()
                    batch_documents.clear(); batch_metadatas.clear()

            total_bytes_processed += file_size
            sys.stdout.write(f"\r✅ [{idx}/{total_files}] {filename} ({size_str}) | Done: {file_chunks_added} chunks\n")
            sys.stdout.flush()

        except Exception as e:
            sys.stdout.write(f"\r❌ [{idx}/{total_files}] {filename} ({size_str}) | Error: {str(e)[:60]}\n")
            sys.stdout.flush()
            failed_files.append({"path": filepath, "chunk": -1, "reason": str(e)[:150]})

    if batch_ids:
        collection.upsert(
            ids=batch_ids, embeddings=batch_embeddings,
            documents=batch_documents, metadatas=batch_metadatas
        )

    elapsed = time.time() - start_time
    print(f"\n{'='*60}")
    print(f"🎉 SELESAI dalam {elapsed//60:.0f}m {elapsed%60:.0f}s")
    print(f"{'='*60}")
    print(f"   ✅ New chunks added   : {total_chunks}")
    print(f"   ⏭️  Skipped (exist)    : {skipped_existing}")
    print(f"   ❌ Error              : {len(failed_files)}")
    print(f"   📦 Total files        : {total_files}")
    print(f"   💾 Total processed    : {format_size(total_bytes_processed)}")
    print(f"{'='*60}\n")

    if failed_files:
        print(f"❌ DAFTAR FILE YANG GAGAL ({len(failed_files)}):")
        print("-" * 60)
        for i, err in enumerate(failed_files[:10], 1):
            print(f"{i}. {err['path']} (chunk {err['chunk']})")
            print(f"   Reason: {err['reason']}\n")
        try:
            with open(ERROR_LOG_FILE, "w", encoding="utf-8") as f:
                f.write(f"# Ingest Error Log - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# Total Failed: {len(failed_files)}\n\n")
                for err in failed_files:
                    f.write(f"PATH: {err['path']}\nCHUNK: {err['chunk']}\nREASON: {err['reason']}\n")
                    f.write("-" * 60 + "\n")
            print(f"💾 Full log: {ERROR_LOG_FILE}")
        except Exception as e:
            print(f"⚠️ Gagal save log: {e}")
    else:
        print("✅ Tidak ada file yang gagal!")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ingest dokumen Markdown/PDF ke ChromaDB")
    parser.add_argument("--docs", default="./data/thm",
                        help="Path folder dokumen (default: ./data/thm)")
    args = parser.parse_args()

    if not os.path.exists(args.docs):
        print(f"❌ Folder tidak ditemukan: {args.docs}")
        exit(1)

    ingest_folder(args.docs)
