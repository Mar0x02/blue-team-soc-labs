"""
ingest-yml.py - Production-Ready Sigma Repo Ingestion with Error Tracking
Usage: python ingest-yml.py --docs /path/to/sigma/rules
"""

import os
import sys
import argparse
import hashlib
import time
import json
from datetime import datetime
import chromadb
import ollama
import yaml

# ============ CONFIG ============
CHROMA_PATH = "./chroma_db"
COLLECTION_NAME = "soc_knowledge"
EMBED_MODEL = "nomic-embed-text"
BATCH_SIZE = 50
SKIP_STATUSES = ["deprecated", "unsupported"]
ERROR_LOG_FILE = "./ingest_yml_errors.log"
MAX_EMBED_CHARS = 8000  # nomic-embed-text context = 8192 tokens, BERT tokenizer ~3-4 chars/token
EMBED_RETRIES = 3
EMBED_RETRY_DELAY = 5
# ================================

ollama_client = ollama.Client(host='http://127.0.0.1:11434')

failed_files = []
skipped_files = []

def format_size(size_bytes):
    if size_bytes < 1024:
        return f"{size_bytes}B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes/1024:.1f}KB"
    else:
        return f"{size_bytes/(1024*1024):.1f}MB"

def generate_unique_id(filepath):
    """Generate unique ID dari full path"""
    return hashlib.md5(filepath.encode("utf-8")).hexdigest()

def extract_sigma_indicators(detection_block):
    """Menyelam ke dalam blok detection buat cari indikator teknis."""
    indicators = {
        "event_ids": set(),
        "images": set(),
        "filenames": set(),
        "commands": set()
    }

    def recursive_search(data):
        if isinstance(data, dict):
            for key, value in data.items():
                k = key.lower() if isinstance(key, str) else ""

                if k == "eventid":
                    if isinstance(value, list):
                        indicators["event_ids"].update(str(v) for v in value)
                    else:
                        indicators["event_ids"].add(str(value))

                elif k in ["image", "parentimage", "originalfilename"]:
                    indicators["images"].add(str(value).lower())
                elif k in ["targetfilename", "filename"]:
                    indicators["filenames"].add(str(value).lower())
                elif k == "commandline":
                    indicators["commands"].add(str(value).lower())

                recursive_search(value)

        elif isinstance(data, list):
            for item in data:
                recursive_search(item)

    recursive_search(detection_block)

    metadata = {}
    if indicators["event_ids"]:
        metadata["event_ids"] = ", ".join(indicators["event_ids"])
    if indicators["images"]:
        clean = []
        for img in indicators["images"]:
            name = os.path.basename(img.replace("\\", "/").strip("*").strip())
            if name:
                clean.append(name)
        metadata["process_names"] = ", ".join(set(clean))
    if indicators["filenames"]:
        metadata["target_files"] = ", ".join(list(indicators["filenames"])[:5])
    if indicators["commands"]:
        metadata["command_patterns"] = ", ".join(list(indicators["commands"])[:3])

    return metadata

def extract_all_indicators(detection_block):
    """Ambil semua string/angka dari list di dalam detection block."""
    indicators = []

    def recurse(data):
        if isinstance(data, list):
            for item in data:
                if isinstance(item, (str, int, float)):
                    indicators.append(str(item))
                else:
                    recurse(item)
        elif isinstance(data, dict):
            for key, value in data.items():
                if key == "condition":
                    continue
                recurse(value)

    recurse(detection_block)
    return indicators


def build_indicator_chunks(doc, base_metadata, chunk_size=30):
    """
    Pecah rule besar jadi beberapa chunk: header + batch of N indicators.
    Return list of (chunk_text, chunk_metadata).
    """
    header_parts = []
    if doc.get("title"):       header_parts.append(f"Title: {doc['title']}")
    if doc.get("description"): header_parts.append(f"Description: {doc['description']}")
    tags = doc.get("tags", [])
    if isinstance(tags, list): header_parts.append(f"Tags: {', '.join(str(t) for t in tags)}")
    if doc.get("level"):       header_parts.append(f"Level: {doc['level']}")
    logsource = doc.get("logsource", {})
    if isinstance(logsource, dict):
        ls = [v for v in [logsource.get("product"), logsource.get("category"), logsource.get("service")] if v]
        if ls: header_parts.append(f"Logsource: {' / '.join(ls)}")
    header = "\n".join(header_parts)

    indicators = extract_all_indicators(doc.get("detection", {}))

    if not indicators:
        return [(header, {**base_metadata, "embed_mode": "semantic_fallback"})]

    chunks = []
    for i in range(0, len(indicators), chunk_size):
        batch = indicators[i:i + chunk_size]
        chunk_text = header + "\nIndicators:\n" + "\n".join(f"- {ind}" for ind in batch)
        chunks.append((chunk_text, {
            **base_metadata,
            "embed_mode": "chunked_indicators",
            "chunk_index": str(i // chunk_size),
            "total_indicators": str(len(indicators)),
        }))

    return chunks


def parse_yaml_rules(filepath):
    """
    Parse YAML file. Return list of (raw_text, semantic_text, metadata, doc).
    raw_text = full yaml.dump untuk embedding normal.
    doc dikembalikan untuk keperluan chunking kalau raw_text terlalu panjang.
    Raise exception kalau ada error fatal.
    """
    rules = []

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            raw_content = f.read()
    except Exception as e:
        raise Exception(f"Gagal baca file: {e}")

    try:
        documents = list(yaml.safe_load_all(raw_content))
    except yaml.YAMLError as e:
        raise Exception(f"YAML syntax error: {str(e)[:100]}")

    for doc in documents:
        if not isinstance(doc, dict):
            continue

        status = str(doc.get("status", "")).lower()
        if status in SKIP_STATUSES:
            continue

        if not doc.get("title") and not doc.get("detection"):
            continue

        metadata = {"type": "sigma_rule"}

        if doc.get("title"): metadata["title"] = str(doc["title"])
        if doc.get("description"): metadata["description"] = str(doc["description"])[:500]
        if doc.get("level"): metadata["level"] = str(doc["level"])
        if doc.get("status"): metadata["status"] = str(doc["status"])

        tags = doc.get("tags", [])
        if isinstance(tags, list):
            metadata["tags"] = ", ".join(str(t) for t in tags)

        logsource = doc.get("logsource", {})
        if isinstance(logsource, dict):
            metadata["log_product"] = str(logsource.get("product", "unknown"))
            metadata["log_category"] = str(logsource.get("category", "unknown"))

        detection = doc.get("detection", {})
        if detection:
            tech_meta = extract_sigma_indicators(detection)
            metadata.update(tech_meta)

        raw_text = yaml.dump(doc, allow_unicode=True, default_flow_style=False, sort_keys=False)

        # Semantic fallback text — dipakai kalau raw_text terlalu panjang untuk model
        sem_parts = []
        if doc.get("title"):       sem_parts.append(f"Title: {doc['title']}")
        if doc.get("description"): sem_parts.append(f"Description: {doc['description']}")
        if doc.get("tags"):        sem_parts.append(f"Tags: {', '.join(str(t) for t in doc['tags'])}")
        if doc.get("level"):       sem_parts.append(f"Level: {doc['level']}")
        if isinstance(logsource, dict):
            ls = [v for v in [logsource.get("product"), logsource.get("category"), logsource.get("service")] if v]
            if ls: sem_parts.append(f"Logsource: {' / '.join(ls)}")
        if doc.get("author"):      sem_parts.append(f"Author: {doc['author']}")
        semantic_text = "\n".join(sem_parts)

        if not raw_text.strip() and not semantic_text.strip():
            continue
        rules.append((raw_text, semantic_text, metadata, doc))

    return rules

def embed_text(text):
    """Generate embedding pakai Ollama dengan retry untuk transient error"""
    for attempt in range(1, EMBED_RETRIES + 1):
        try:
            response = ollama_client.embeddings(model=EMBED_MODEL, prompt=text[:MAX_EMBED_CHARS])
            return response["embedding"]
        except Exception as e:
            err = str(e).lower()
            if "context length" in err or "input length" in err:
                raise  # error deterministik, tidak perlu retry
            if attempt < EMBED_RETRIES:
                time.sleep(EMBED_RETRY_DELAY)
            else:
                raise

def ingest_folder(docs_path):
    global failed_files, skipped_files

    client = chromadb.PersistentClient(path=CHROMA_PATH)
    try:
        collection = client.get_collection(COLLECTION_NAME)
        print(f"📂 Collection '{COLLECTION_NAME}' ditemukan. Menambahkan data...")
    except:
        collection = client.create_collection(COLLECTION_NAME)
        print(f"✨ Collection '{COLLECTION_NAME}' dibuat baru.")

    docs_path = os.path.abspath(docs_path)
    if os.name == 'nt' and not docs_path.startswith("\\\\?\\"):
        docs_path = "\\\\?\\" + docs_path

    # Load existing IDs untuk skip yang sudah ada (resume support)
    print("🔍 Checking existing rules di database...")
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
    print(f"✅ Found {len(existing_ids)} rules yang udah ada. Akan skip yang duplikat.\n")

    all_yaml_files = []
    for root, _, files in os.walk(docs_path):
        for f in files:
            if f.endswith((".yml", ".yaml")):
                all_yaml_files.append(os.path.join(root, f))

    total_files = len(all_yaml_files)
    print(f"🔍 Ditemukan {total_files} file YAML.")
    print(f"⚡ Model: {EMBED_MODEL}")
    print(f"🚀 Mulai proses...\n")

    batch_ids, batch_embeddings, batch_documents, batch_metadatas = [], [], [], []
    total_rules = 0
    skipped_existing = 0
    total_bytes_processed = 0
    start_time = time.time()

    for idx, filepath in enumerate(all_yaml_files, 1):
        filename = os.path.basename(filepath)
        file_size = os.path.getsize(filepath)
        size_str = format_size(file_size)

        sys.stdout.write(f"\r🔄 [{idx}/{total_files}] {filename} ({size_str}) | Processing...")
        sys.stdout.flush()

        if idx % 100 == 0 or idx == total_files:
            elapsed = time.time() - start_time
            rate = idx / elapsed if elapsed > 0 else 0
            eta = (total_files - idx) / rate if rate > 0 else 0
            sys.stdout.write(
                f"\n  📊 Progress: {idx}/{total_files} ({idx*100//total_files}%) | "
                f"Rules: {total_rules} | Skip exist: {skipped_existing} | Skip invalid: {len(skipped_files)} | "
                f"Failed: {len(failed_files)} | "
                f"Processed: {format_size(total_bytes_processed)} | "
                f"ETA: {eta//60:.0f}m{eta%60:.0f}s\n"
            )
            sys.stdout.flush()

        try:
            rules = parse_yaml_rules(filepath)

            if not rules:
                skipped_files.append({"path": filepath, "reason": "File kosong, deprecated, atau tidak valid"})
                sys.stdout.write(f"\r⏭️  [{idx}/{total_files}] {filename} ({size_str}) | Skipped\n")
                sys.stdout.flush()
                continue

            file_rules_added = 0
            for rule_idx, (raw_text, semantic_text, metadata, doc) in enumerate(rules):
                if not raw_text.strip() and not semantic_text.strip():
                    continue

                doc_id = generate_unique_id(f"{filepath}__{rule_idx}")
                if doc_id in existing_ids:
                    skipped_existing += 1
                    continue

                rel_path = filepath.replace(docs_path, "").lstrip(os.sep).lstrip("\\\\?\\").lstrip(os.sep)
                embedding_ok = False

                try:
                    embedding = embed_text(raw_text)
                    embedding_ok = True
                except Exception as e:
                    err = str(e).lower()
                    if "context length" in err or "input length" in err:
                        # Rule terlalu besar — chunk indicators ke beberapa embedding
                        for chunk_idx, (chunk_text, chunk_meta) in enumerate(
                            build_indicator_chunks(doc, dict(metadata))
                        ):
                            chunk_id = generate_unique_id(f"{filepath}__{rule_idx}__chunk_{chunk_idx}")
                            if chunk_id in existing_ids:
                                skipped_existing += 1
                                continue
                            try:
                                chunk_emb = embed_text(chunk_text)
                            except Exception as e2:
                                failed_files.append({"path": filepath, "reason": f"Chunk {chunk_idx} embed error: {str(e2)[:100]}"})
                                continue
                            chunk_meta["source"] = filename
                            chunk_meta["path"] = os.path.dirname(rel_path)
                            batch_ids.append(chunk_id)
                            batch_embeddings.append(chunk_emb)
                            batch_documents.append(chunk_text)
                            batch_metadatas.append(chunk_meta)
                            total_rules += 1
                            file_rules_added += 1
                            if len(batch_ids) >= BATCH_SIZE:
                                collection.upsert(
                                    ids=batch_ids, embeddings=batch_embeddings,
                                    documents=batch_documents, metadatas=batch_metadatas
                                )
                                batch_ids.clear(); batch_embeddings.clear()
                                batch_documents.clear(); batch_metadatas.clear()
                    else:
                        failed_files.append({"path": filepath, "reason": f"Embedding error: {str(e)[:100]}"})

                if not embedding_ok:
                    continue

                metadata["source"] = filename
                metadata["path"] = os.path.dirname(rel_path)

                batch_ids.append(doc_id)
                batch_embeddings.append(embedding)
                batch_documents.append(raw_text)
                batch_metadatas.append(metadata)
                total_rules += 1
                file_rules_added += 1

                if len(batch_ids) >= BATCH_SIZE:
                    collection.upsert(
                        ids=batch_ids, embeddings=batch_embeddings,
                        documents=batch_documents, metadatas=batch_metadatas
                    )
                    batch_ids.clear(); batch_embeddings.clear()
                    batch_documents.clear(); batch_metadatas.clear()

            total_bytes_processed += file_size
            sys.stdout.write(f"\r✅ [{idx}/{total_files}] {filename} ({size_str}) | Done: {file_rules_added} rules\n")
            sys.stdout.flush()

        except Exception as e:
            sys.stdout.write(f"\r❌ [{idx}/{total_files}] {filename} ({size_str}) | Error: {str(e)[:60]}\n")
            sys.stdout.flush()
            failed_files.append({"path": filepath, "reason": str(e)[:150]})

    if batch_ids:
        collection.upsert(
            ids=batch_ids, embeddings=batch_embeddings,
            documents=batch_documents, metadatas=batch_metadatas
        )

    elapsed = time.time() - start_time
    print(f"\n{'='*60}")
    print(f"🎉 SELESAI dalam {elapsed//60:.0f}m {elapsed%60:.0f}s")
    print(f"{'='*60}")
    print(f"   ✅ Rules berhasil di-ingest  : {total_rules}")
    print(f"   ⏭️  Skip (sudah ada di DB)    : {skipped_existing}")
    print(f"   ⏭️  Skip (deprecated/kosong)  : {len(skipped_files)}")
    print(f"   ❌ Gagal diproses             : {len(failed_files)}")
    print(f"   📦 Total files               : {total_files}")
    print(f"   💾 Total processed           : {format_size(total_bytes_processed)}")
    print(f"{'='*60}\n")

    if failed_files:
        print(f"❌ DAFTAR FILE YANG GAGAL ({len(failed_files)} files):")
        print("-" * 60)
        for i, err in enumerate(failed_files, 1):
            print(f"{i}. {err['path']}")
            print(f"   Reason: {err['reason']}\n")
        try:
            with open(ERROR_LOG_FILE, "w", encoding="utf-8") as f:
                f.write(f"# Ingest Error Log - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# Total Failed: {len(failed_files)}\n\n")
                for err in failed_files:
                    f.write(f"PATH: {err['path']}\nREASON: {err['reason']}\n")
                    f.write("-" * 60 + "\n")
            print(f"💾 Detail error disimpan ke: {ERROR_LOG_FILE}")
        except Exception as e:
            print(f"⚠️ Gagal save log file: {e}")
    else:
        print("✅ Tidak ada file yang gagal! Semua berhasil diproses.")

    print(f"\n{'='*60}\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ingest SigmaHQ repo ke ChromaDB")
    parser.add_argument("--docs", default="./data/sigma/sigma-master/rules",
                        help="Path ke folder rules (default: ./data/sigma/sigma-master/rules)")
    args = parser.parse_args()

    clean_path = args.docs.replace("\\\\?\\", "")
    if not os.path.exists(clean_path):
        print(f"❌ Folder gak ketemu: {clean_path}")
        print(f"   Jalankan: git clone --depth=1 https://github.com/SigmaHQ/sigma data/sigma/sigma-master")
        exit(1)

    if os.name == 'nt':
        args.docs = "\\\\?\\" + os.path.abspath(clean_path)
    else:
        args.docs = os.path.abspath(clean_path)

    ingest_folder(args.docs)
