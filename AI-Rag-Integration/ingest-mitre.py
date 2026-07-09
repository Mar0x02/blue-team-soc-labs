"""
ingest-mitre.py - MITRE ATT&CK Ingestion (Production-Ready)
Handle bundle format, anti-duplicate, resume capability
Usage: python ingest-mitre.py --docs /path/to/mitre/cti/enterprise-attack
"""

import os
import json
import argparse
import hashlib
import time
import sys
import chromadb
import ollama
from datetime import datetime

# Config
CHROMA_PATH = "./chroma_db"
COLLECTION_NAME = "soc_knowledge"
EMBED_MODEL = "nomic-embed-text"
BATCH_SIZE = 50
ERROR_LOG_FILE = "./ingest_mitre_errors.log"
MAX_EMBED_CHARS = 8000  # nomic-embed-text context = 8192 tokens, BERT tokenizer ~3-4 chars/token
EMBED_RETRIES = 3
EMBED_RETRY_DELAY = 5

ollama_client = ollama.Client(host='http://127.0.0.1:11434')
failed_files = []

def format_size(size_bytes):
    if size_bytes < 1024:
        return f"{size_bytes}B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes/1024:.1f}KB"
    else:
        return f"{size_bytes/(1024*1024):.1f}MB"

def extract_mitre_object(obj):
    """Ekstrak 1 STIX object dari MITRE ATT&CK"""
    try:
        obj_type = obj.get("type", "unknown")

        if obj_type in ["relationship", "x-mitre-matrix", "x-mitre-tactic",
                       "marking-definition", "identity"]:
            return None, None, None

        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            return None, None, None

        name = obj.get("name")
        if not name:
            return None, None, None

        stix_id = obj.get("id", "")
        if not stix_id:
            stix_id = f"{obj_type}--{name}"

        description = obj.get("description", "")

        metadata = {
            "type": "mitre_attack",
            "object_type": obj_type,
            "stix_id": stix_id,
            "name": name,
        }

        if obj_type == "attack-pattern":
            external_refs = obj.get("external_references", [])
            for ref in external_refs:
                if ref.get("source_name") == "mitre-attack":
                    metadata["technique_id"] = ref.get("external_id", "")
                    break

            kill_chain = obj.get("kill_chain_phases", [])
            tactics = [phase.get("phase_name") for phase in kill_chain]
            if tactics:
                metadata["tactics"] = ", ".join(tactics)

            platforms = obj.get("x_mitre_platforms", [])
            if platforms:
                metadata["platforms"] = ", ".join(platforms)

            data_sources = obj.get("x_mitre_data_sources", [])
            if data_sources:
                metadata["data_sources"] = ", ".join(data_sources)

            detection = obj.get("x_mitre_detection", "")
            if detection:
                metadata["detection"] = detection[:300]

        elif obj_type == "course-of-action":
            external_refs = obj.get("external_references", [])
            for ref in external_refs:
                if ref.get("source_name") == "mitre-attack":
                    metadata["mitigation_id"] = ref.get("external_id", "")
                    break

        elif obj_type == "intrusion-set":
            external_refs = obj.get("external_references", [])
            for ref in external_refs:
                if ref.get("source_name") == "mitre-attack":
                    metadata["group_id"] = ref.get("external_id", "")
                    break

            aliases = obj.get("aliases", [])
            if aliases:
                metadata["aliases"] = ", ".join(aliases[:5])

        elif obj_type in ["malware", "tool"]:
            external_refs = obj.get("external_references", [])
            for ref in external_refs:
                if ref.get("source_name") == "mitre-attack":
                    metadata["software_id"] = ref.get("external_id", "")
                    break

            platforms = obj.get("x_mitre_platforms", [])
            if platforms:
                metadata["platforms"] = ", ".join(platforms)

        text_parts = [f"Name: {name}"]

        if obj_type == "attack-pattern" and metadata.get("technique_id"):
            text_parts.insert(0, f"Technique ID: {metadata['technique_id']}")
        elif obj_type == "intrusion-set" and metadata.get("group_id"):
            text_parts.insert(0, f"Group ID: {metadata['group_id']}")
        elif obj_type in ["malware", "tool"] and metadata.get("software_id"):
            text_parts.insert(0, f"Software ID: {metadata['software_id']}")
        elif obj_type == "course-of-action" and metadata.get("mitigation_id"):
            text_parts.insert(0, f"Mitigation ID: {metadata['mitigation_id']}")

        if metadata.get("tactics"):
            text_parts.append(f"Tactics: {metadata['tactics']}")
        if metadata.get("platforms"):
            text_parts.append(f"Platforms: {metadata['platforms']}")
        if metadata.get("aliases"):
            text_parts.append(f"Aliases: {metadata['aliases']}")

        if description:
            text_parts.append(f"Description: {description[:500]}")
            metadata["description"] = description[:500]

        full_text = "\n".join(text_parts)
        return full_text, metadata, stix_id

    except Exception:
        return None, None, None

def process_bundle_file(filepath, collection, existing_ids, batch_data):
    """Process file JSON yang berisi bundle. Return (objects_added, objects_skipped)."""
    objects_processed = 0
    objects_skipped = 0

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)

        if isinstance(data, dict) and "objects" in data:
            objects = data.get("objects", [])
        elif isinstance(data, list):
            objects = data
        else:
            objects = [data]

        for obj in objects:
            full_text, metadata, stix_id = extract_mitre_object(obj)

            if not full_text or not metadata or not stix_id:
                continue

            doc_id = hashlib.md5(stix_id.encode("utf-8")).hexdigest()

            if doc_id in existing_ids:
                objects_skipped += 1
                continue

            if doc_id in batch_data["ids"]:
                continue

            metadata["source"] = os.path.basename(filepath)

            try:
                for attempt in range(1, EMBED_RETRIES + 1):
                    try:
                        embedding = ollama_client.embeddings(model=EMBED_MODEL, prompt=full_text[:MAX_EMBED_CHARS])["embedding"]
                        break
                    except Exception as e:
                        if attempt < EMBED_RETRIES:
                            time.sleep(EMBED_RETRY_DELAY)
                        else:
                            raise
            except Exception as e:
                failed_files.append({
                    "path": filepath,
                    "object": metadata.get("name", "Unknown"),
                    "reason": f"Embed: {str(e)[:50]}"
                })
                continue

            batch_data["ids"].append(doc_id)
            batch_data["embeddings"].append(embedding)
            batch_data["documents"].append(full_text)
            batch_data["metadatas"].append(metadata)
            objects_processed += 1

            if len(batch_data["ids"]) >= BATCH_SIZE:
                collection.upsert(
                    ids=batch_data["ids"],
                    embeddings=batch_data["embeddings"],
                    documents=batch_data["documents"],
                    metadatas=batch_data["metadatas"]
                )
                batch_data["ids"].clear(); batch_data["embeddings"].clear()
                batch_data["documents"].clear(); batch_data["metadatas"].clear()

        return objects_processed, objects_skipped

    except Exception as e:
        raise Exception(f"Parse error: {str(e)[:100]}")

def ingest_mitre_folder(docs_path):
    client = chromadb.PersistentClient(path=CHROMA_PATH)
    try:
        collection = client.get_collection(COLLECTION_NAME)
        print(f"📂 Collection '{COLLECTION_NAME}' ditemukan.")
    except:
        collection = client.create_collection(COLLECTION_NAME)
        print(f"✨ Collection '{COLLECTION_NAME}' dibuat baru.")

    print("🔍 Checking existing MITRE objects di database...")
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
    print(f"✅ Found {len(existing_ids)} entries yang udah ada.\n")

    all_json_files = []
    for root, _, files in os.walk(docs_path):
        for f in files:
            if f.endswith(".json"):
                all_json_files.append(os.path.join(root, f))

    total_files = len(all_json_files)
    print(f"🔍 Ditemukan {total_files} file MITRE JSON.")
    print(f"⚡ Model: {EMBED_MODEL}")
    print(f"🚀 Mulai proses...\n")

    batch_data = {"ids": [], "embeddings": [], "documents": [], "metadatas": []}
    total_objects = 0
    skipped_existing = 0
    total_bytes_processed = 0
    start_time = time.time()

    for idx, filepath in enumerate(all_json_files, 1):
        filename = os.path.basename(filepath)
        file_size = os.path.getsize(filepath)
        size_str = format_size(file_size)

        sys.stdout.write(f"\r🔄 [{idx}/{total_files}] {filename} ({size_str}) | Processing...")
        sys.stdout.flush()

        if idx % 50 == 0 or idx == total_files:
            elapsed = time.time() - start_time
            rate = idx / elapsed if elapsed > 0 else 0
            eta = (total_files - idx) / rate if rate > 0 else 0
            sys.stdout.write(
                f"\n  📊 Progress: {idx}/{total_files} ({idx*100//total_files}%) | "
                f"New: {total_objects} | Skipped: {skipped_existing} | "
                f"Failed: {len(failed_files)} | "
                f"Processed: {format_size(total_bytes_processed)} | "
                f"ETA: {eta//60:.0f}m{eta%60:.0f}s\n"
            )
            sys.stdout.flush()

        try:
            objects_added, objects_skipped = process_bundle_file(filepath, collection, existing_ids, batch_data)
            total_objects += objects_added
            skipped_existing += objects_skipped
            total_bytes_processed += file_size

            sys.stdout.write(f"\r✅ [{idx}/{total_files}] {filename} ({size_str}) | Added: {objects_added} objects\n")
            sys.stdout.flush()

        except Exception as e:
            sys.stdout.write(f"\r❌ [{idx}/{total_files}] {filename} ({size_str}) | Error: {str(e)[:60]}\n")
            sys.stdout.flush()
            failed_files.append({"path": filepath, "object": "FILE_LEVEL", "reason": str(e)[:100]})

    if batch_data["ids"]:
        collection.upsert(
            ids=batch_data["ids"],
            embeddings=batch_data["embeddings"],
            documents=batch_data["documents"],
            metadatas=batch_data["metadatas"]
        )

    elapsed = time.time() - start_time
    print(f"\n{'='*60}")
    print(f"🎉 SELESAI dalam {elapsed//60:.0f}m {elapsed%60:.0f}s")
    print(f"{'='*60}")
    print(f"   ✅ New objects added   : {total_objects}")
    print(f"   ⏭️  Skipped (exist)     : {skipped_existing}")
    print(f"   ❌ Error               : {len(failed_files)}")
    print(f"   📦 Total files         : {total_files}")
    print(f"   💾 Total processed     : {format_size(total_bytes_processed)}")
    print(f"{'='*60}\n")

    if failed_files:
        print(f"❌ ERROR ({len(failed_files)}):")
        for i, err in enumerate(failed_files[:10], 1):
            print(f"{i}. [{err.get('object', 'N/A')}] {err['path']}")
            print(f"   -> {err['reason']}\n")
        try:
            with open(ERROR_LOG_FILE, "w", encoding="utf-8") as f:
                f.write(f"# Ingest Error Log - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# Total Failed: {len(failed_files)}\n\n")
                for err in failed_files:
                    f.write(f"{err}\n")
            print(f"💾 Full log: {ERROR_LOG_FILE}")
        except Exception as e:
            print(f"⚠️ Gagal save log: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ingest MITRE ATT&CK ke ChromaDB")
    parser.add_argument("--docs", default="./data/cti/cti-master/enterprise-attack",
                        help="Path ke folder MITRE CTI (default: ./data/cti/cti-master/enterprise-attack)")
    args = parser.parse_args()

    if not os.path.exists(args.docs):
        print(f"❌ Folder gak ketemu: {args.docs}")
        print(f"   Jalankan: git clone --depth=1 https://github.com/mitre/cti data/cti/cti-master")
        exit(1)

    ingest_mitre_folder(args.docs)
