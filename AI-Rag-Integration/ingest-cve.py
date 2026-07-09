"""
ingest-cve.py - Smart CVE Database Ingestion
Usage:
  python ingest-cve.py --year-from 2022 --year-to 2026 --min-severity HIGH
  python ingest-cve.py --year-from 2024
  python ingest-cve.py --all
"""

import os
import re
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
ERROR_LOG_FILE = "./ingest_cve_errors.log"
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

def generate_unique_id(text):
    return hashlib.md5(text.encode("utf-8")).hexdigest()

def extract_cve_data(json_data):
    """Ekstrak data penting dari JSON CVE v5"""
    try:
        cve_meta = json_data.get("cveMetadata", {})
        cve_id = cve_meta.get("cveId", "UNKNOWN")
        state = cve_meta.get("state", "UNKNOWN")

        if state != "PUBLISHED":
            return None, None

        containers = json_data.get("containers", {})
        cna_data = containers.get("cna", {})

        # Description
        descriptions = cna_data.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        if not description and descriptions:
            description = descriptions[0].get("value", "")

        # CVSS score + vector detail
        cvss_score = None
        cvss_severity = None
        attack_vector = None
        privileges_required = None
        metrics = cna_data.get("metrics", [])
        for metric in metrics:
            for version in ["cvssV3_1", "cvssV3_0", "cvssV2_0"]:
                if version in metric:
                    cvss_data = metric[version]
                    cvss_score = cvss_data.get("baseScore")
                    cvss_severity = cvss_data.get("baseSeverity", "UNKNOWN")
                    attack_vector = cvss_data.get("attackVector")
                    privileges_required = cvss_data.get("privilegesRequired")
                    break
            if cvss_score:
                break

        # CWE
        cwe_ids = []
        for pt in cna_data.get("problemTypes", []):
            for desc in pt.get("descriptions", []):
                cwe_id = desc.get("cweId")
                if cwe_id:
                    cwe_ids.append(cwe_id)

        # Affected products + versions
        affected_products = []
        affected_versions = []
        for aff in cna_data.get("affected", []):
            vendor  = aff.get("vendor", "Unknown")[:80]
            product = aff.get("product", "Unknown")
            # Product kadang berisi list 50+ model numbers dalam 1 string — ambil model pertama saja
            if len(product) > 80:
                product = product.split(",")[0].strip()
            affected_products.append(f"{vendor} {product}")
            for ver in aff.get("versions", []):
                v = ver.get("version", "")
                lte = ver.get("lessThanOrEqual", "")
                if v and lte:
                    affected_versions.append(f"{product} {v}–{lte}")
                elif v:
                    affected_versions.append(f"{product} {v}")

        # References
        references = []
        for ref in cna_data.get("references", [])[:5]:
            url = ref.get("url")
            if url:
                references.append(url)

        # CAPEC + impact description
        capec_ids = []
        impact_descs = []
        for impact in cna_data.get("impacts", []):
            capec = impact.get("capecId")
            if capec:
                capec_ids.append(capec)
            for d in impact.get("descriptions", []):
                if d.get("lang") == "en" and d.get("value"):
                    impact_descs.append(d["value"])

        # Solution
        solution = ""
        for sol in cna_data.get("solutions", []):
            if sol.get("lang") == "en" and sol.get("value"):
                solution = sol["value"]
                break

        # SSVC exploitation status (dari adp block)
        exploitation_status = None
        for adp in containers.get("adp", []):
            for metric in adp.get("metrics", []):
                ssvc = metric.get("other", {})
                if ssvc.get("type") == "ssvc":
                    for opt in ssvc.get("content", {}).get("options", []):
                        if "Exploitation" in opt:
                            exploitation_status = opt["Exploitation"]

        date_published = cve_meta.get("datePublished", "")[:10]

        # === Metadata ===
        metadata = {
            "type": "cve_entry",
            "cve_id": cve_id,
            "description": description[:500],
            "date_published": date_published,
        }
        if cvss_score:           metadata["cvss_score"] = str(cvss_score)
        if cvss_severity:        metadata["cvss_severity"] = cvss_severity
        if attack_vector:        metadata["attack_vector"] = attack_vector
        if privileges_required:  metadata["privileges_required"] = privileges_required
        if cwe_ids:              metadata["cwe_ids"] = ", ".join(cwe_ids[:3])
        if capec_ids:            metadata["capec_ids"] = ", ".join(capec_ids[:3])
        if affected_products:    metadata["affected_products"] = ", ".join(affected_products[:5])
        if affected_versions:    metadata["affected_versions"] = ", ".join(affected_versions[:5])
        if references:           metadata["references"] = ", ".join(references)
        if exploitation_status:  metadata["exploitation"] = exploitation_status
        if solution:             metadata["solution"] = solution[:300]

        # === Embedding text ===
        text_parts = [f"CVE ID: {cve_id}"]
        text_parts.append(f"Description: {description}")
        if cvss_score:
            av  = f", Attack Vector: {attack_vector}" if attack_vector else ""
            pr  = f", Privileges Required: {privileges_required}" if privileges_required else ""
            text_parts.append(f"CVSS: {cvss_score} ({cvss_severity}){av}{pr}")
        if cwe_ids:
            text_parts.append(f"CWE: {', '.join(cwe_ids)}")
        if capec_ids:
            text_parts.append(f"CAPEC: {', '.join(capec_ids)}")
        if impact_descs:
            text_parts.append(f"Impact: {', '.join(impact_descs[:2])}")
        if affected_products:
            text_parts.append(f"Affected: {', '.join(affected_products[:5])}")
        if affected_versions:
            text_parts.append(f"Affected Versions: {', '.join(affected_versions[:5])}")
        if exploitation_status:
            text_parts.append(f"Exploitation: {exploitation_status}")
        if solution:
            text_parts.append(f"Solution: {solution[:300]}")

        full_text = "\n".join(text_parts)
        return full_text, metadata

    except Exception:
        return None, None

def ingest_cve_folder(docs_path, year_from=None, year_to=None, min_severity=None):
    client = chromadb.PersistentClient(path=CHROMA_PATH)
    try:
        collection = client.get_collection(COLLECTION_NAME)
        print(f"📂 Collection '{COLLECTION_NAME}' ditemukan.")
    except:
        collection = client.create_collection(COLLECTION_NAME)
        print(f"✨ Collection '{COLLECTION_NAME}' dibuat baru.")

    print("🔍 Checking existing CVEs di database...")
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
            if not (f.endswith(".json") and f.startswith("CVE-")):
                continue
            if year_from or year_to:
                year_match = re.search(r'CVE-(\d{4})-', f)
                if not year_match:
                    continue
                file_year = int(year_match.group(1))
                if year_from and file_year < year_from:
                    continue
                if year_to and file_year > year_to:
                    continue
            all_json_files.append(os.path.join(root, f))

    total_files = len(all_json_files)
    print(f"🔍 Ditemukan {total_files} file CVE JSON.")
    if year_from or year_to:
        frm = str(year_from) if year_from else "awal"
        to  = str(year_to)   if year_to   else "sekarang"
        print(f"📅 Filter: Year {frm} – {to}")
    if min_severity:
        print(f"⚠️  Filter: Min Severity {min_severity}")
    print(f"⚡ Model: {EMBED_MODEL}")
    print(f"🚀 Mulai proses...\n")

    batch_ids, batch_embeddings, batch_documents, batch_metadatas = [], [], [], []
    total_cves = 0
    skipped_existing = 0
    skipped_filter = 0
    total_bytes_processed = 0
    start_time = time.time()

    severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}
    min_sev_level = severity_order.get(min_severity, 0) if min_severity else 0

    for idx, filepath in enumerate(all_json_files, 1):
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
                f"New: {total_cves} | Skipped: {skipped_existing} | "
                f"Filtered: {skipped_filter} | Failed: {len(failed_files)} | "
                f"Processed: {format_size(total_bytes_processed)} | "
                f"ETA: {eta//60:.0f}m{eta%60:.0f}s\n"
            )
            sys.stdout.flush()

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                json_data = json.load(f)

            full_text, metadata = extract_cve_data(json_data)

            if not full_text or not metadata:
                sys.stdout.write(f"\r⏭️  [{idx}/{total_files}] {filename} | Skipped (not published/invalid)\n")
                sys.stdout.flush()
                continue

            if min_severity:
                cve_severity = metadata.get("cvss_severity", "NONE")
                cve_level = severity_order.get(cve_severity, 0)
                if cve_level < min_sev_level:
                    skipped_filter += 1
                    continue

            # ID berbasis cve_id agar stabil meski extraction logic diupdate
            doc_id = generate_unique_id(metadata["cve_id"])
            if doc_id in existing_ids:
                skipped_existing += 1
                continue

            metadata["source"] = filename

            embedding_ok = False
            try:
                for attempt in range(1, EMBED_RETRIES + 1):
                    try:
                        embedding = ollama_client.embeddings(model=EMBED_MODEL, prompt=full_text[:MAX_EMBED_CHARS])["embedding"]
                        embedding_ok = True
                        break
                    except Exception as e:
                        err = str(e).lower()
                        if "context length" in err or "input length" in err:
                            raise  # deterministik, tidak perlu retry
                        if attempt < EMBED_RETRIES:
                            time.sleep(EMBED_RETRY_DELAY)
                        else:
                            raise
            except Exception as e:
                err = str(e).lower()
                if "context length" in err or "input length" in err:
                    # Fallback: embed field minimal yang pasti muat
                    fallback_text = f"CVE ID: {metadata['cve_id']}\nDescription: {metadata['description'][:500]}"
                    if metadata.get("cvss_severity"):
                        fallback_text += f"\nCVSS: {metadata.get('cvss_score')} ({metadata['cvss_severity']})"
                    if metadata.get("affected_products"):
                        fallback_text += f"\nAffected: {metadata['affected_products'][:200]}"
                    try:
                        embedding = ollama_client.embeddings(model=EMBED_MODEL, prompt=fallback_text)["embedding"]
                        metadata["embed_mode"] = "fallback"
                        embedding_ok = True
                        full_text = fallback_text
                    except Exception as e2:
                        failed_files.append({"path": filepath, "cve": metadata.get("cve_id", "Unknown"), "reason": f"Embed fallback error: {str(e2)[:50]}"})
                else:
                    failed_files.append({"path": filepath, "cve": metadata.get("cve_id", "Unknown"), "reason": f"Embed: {str(e)[:50]}"})

            if not embedding_ok:
                continue

            batch_ids.append(doc_id)
            batch_embeddings.append(embedding)
            batch_documents.append(full_text)
            batch_metadatas.append(metadata)
            total_cves += 1
            total_bytes_processed += file_size

            if len(batch_ids) >= BATCH_SIZE:
                collection.upsert(ids=batch_ids, embeddings=batch_embeddings, documents=batch_documents, metadatas=batch_metadatas)
                batch_ids.clear(); batch_embeddings.clear(); batch_documents.clear(); batch_metadatas.clear()

            sys.stdout.write(f"\r✅ [{idx}/{total_files}] {filename} | {metadata.get('cve_id')} ({metadata.get('cvss_severity', 'N/A')})\n")
            sys.stdout.flush()

        except Exception as e:
            sys.stdout.write(f"\r❌ [{idx}/{total_files}] {filename} ({size_str}) | Error: {str(e)[:50]}\n")
            sys.stdout.flush()
            failed_files.append({"path": filepath, "cve": "Unknown", "reason": str(e)[:100]})

    if batch_ids:
        collection.upsert(ids=batch_ids, embeddings=batch_embeddings, documents=batch_documents, metadatas=batch_metadatas)

    elapsed = time.time() - start_time
    print(f"\n{'='*60}")
    print(f"🎉 SELESAI dalam {elapsed//60:.0f}m {elapsed%60:.0f}s")
    print(f"{'='*60}")
    print(f"   ✅ New CVEs added      : {total_cves}")
    print(f"   ⏭️  Skipped (exist)     : {skipped_existing}")
    print(f"   🚫 Filtered out        : {skipped_filter}")
    print(f"   ❌ Error               : {len(failed_files)}")
    print(f"   📦 Total files         : {total_files}")
    print(f"   💾 Total processed     : {format_size(total_bytes_processed)}")
    print(f"{'='*60}\n")

    if failed_files:
        print(f"❌ ERROR ({len(failed_files)}):")
        for i, err in enumerate(failed_files[:10], 1):
            print(f"{i}. [{err.get('cve', 'N/A')}] {err['path']} -> {err['reason']}")
        try:
            with open(ERROR_LOG_FILE, "w", encoding="utf-8") as f:
                f.write(f"# Ingest Error Log - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# Total Failed: {len(failed_files)}\n\n")
                for err in failed_files:
                    f.write(f"{err}\n")
            print(f"\n💾 Full log: {ERROR_LOG_FILE}")
        except Exception as e:
            print(f"⚠️ Gagal save log: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ingest CVE database ke ChromaDB")
    parser.add_argument("--docs", default="./data/cvelistV5/cvelistV5-main/cves",
                        help="Path ke folder CVE (default: ./data/cvelistV5/cvelistV5-main/cves)")
    parser.add_argument("--year-from", type=int, help="Filter dari tahun (misal: 2022)")
    parser.add_argument("--year-to",   type=int, help="Filter sampai tahun (misal: 2026)")
    parser.add_argument("--min-severity", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                        help="Filter by minimum severity")
    parser.add_argument("--all", action="store_true", help="Ingest semua (tanpa filter tahun/severity)")

    args = parser.parse_args()

    if not os.path.exists(args.docs):
        print(f"❌ Folder gak ketemu: {args.docs}")
        print(f"   Ekstrak dulu: unzip data/cvelistV5/cvelistV5-main.zip -d data/cvelistV5/")
        exit(1)

    if args.all:
        year_from = year_to = min_severity = None
    else:
        year_from    = args.year_from
        year_to      = args.year_to
        min_severity = args.min_severity

    ingest_cve_folder(args.docs, year_from, year_to, min_severity)
