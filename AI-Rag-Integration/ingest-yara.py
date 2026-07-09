"""
ingest_yara.py - Smart Resume + Real-time File Indicator
Usage: python ingest_yara.py --docs C:\path\to\yara\rules
"""

import os
import re
import argparse
import hashlib
import time
import sys
import chromadb
import ollama

# Config
CHROMA_PATH = "./chroma_db"
COLLECTION_NAME = "soc_knowledge"
EMBED_MODEL = "nomic-embed-text"
BATCH_SIZE = 50
ERROR_LOG_FILE = "./ingest_yara_errors.log"
MAX_EMBED_CHARS = 8000  # nomic-embed-text context = 8192 tokens, BERT tokenizer ~3-4 chars/token
EMBED_RETRIES = 3
EMBED_RETRY_DELAY = 5

ollama_client = ollama.Client(host='http://127.0.0.1:11434')
failed_files = []

def generate_unique_id(text):
    return hashlib.md5(text.encode("utf-8")).hexdigest()

def clean_yara_text(text):
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.DOTALL)
    text = re.sub(r'//.*', '', text)
    text = re.sub(r'\n\s*\n', '\n', text)
    return text.strip()

def extract_yara_metadata(rule_text):
    metadata = {"type": "yara_rule"}
    
    name_match = re.search(r'(?:private\s+|global\s+)?rule\s+(\w+)', rule_text)
    if name_match:
        metadata["rule_name"] = name_match.group(1)
    
    meta_match = re.search(r'meta\s*:(.*?)(strings\s*:|condition\s*:|$)', rule_text, re.DOTALL | re.IGNORECASE)
    if meta_match:
        meta_block = meta_match.group(1)
        for line in meta_block.split('\n'):
            if '=' in line:
                parts = line.split('=', 1)
                if len(parts) == 2:
                    key = parts[0].strip().lower()
                    val = parts[1].strip().strip('"').strip("'").strip()
                    
                    if key in ["description", "author", "date", "hash", "md5", "sha1", "sha256", 
                               "severity", "category", "threat_type", "malware_type", "reference"]:
                        metadata[key] = val[:200]
                        
    if re.search(r'strings\s*:', rule_text, re.IGNORECASE):
        if re.search(r'\{\s*[A-Fa-f0-9\s?]+\}', rule_text):
            metadata["has_hex_strings"] = "true"
        if re.search(r'\$\w+\s*=\s*"', rule_text):
            metadata["has_text_strings"] = "true"

    return metadata

def split_yara_file(content):
    rules = []
    rule_starts = [m.start() for m in re.finditer(r'^\s*(private\s+|global\s+)?rule\s+\w+', content, re.MULTILINE)]
    
    if not rule_starts:
        return rules

    for i, start_idx in enumerate(rule_starts):
        end_limit = rule_starts[i+1] if i + 1 < len(rule_starts) else len(content)
        chunk = content[start_idx:end_limit]
        
        brace_count = 0
        in_rule = False
        actual_end = len(chunk)
        
        for idx, char in enumerate(chunk):
            if char == '{':
                brace_count += 1
                in_rule = True
            elif char == '}':
                brace_count -= 1
                if in_rule and brace_count == 0:
                    actual_end = idx + 1
                    break
        
        full_rule = chunk[:actual_end]
        if full_rule.strip():
            rules.append(full_rule)
            
    return rules

def extract_yara_strings(rule_text):
    """Extract individual string definitions dari strings: block."""
    strings_match = re.search(r'strings\s*:(.*?)(?:condition\s*:|$)', rule_text, re.DOTALL | re.IGNORECASE)
    if not strings_match:
        return []
    strings_block = strings_match.group(1)
    return [l.strip() for l in strings_block.split('\n') if l.strip().startswith('$') and '=' in l]


def build_yara_chunks(rule_text, base_metadata, chunk_size=25):
    """
    Pecah YARA rule besar jadi chunks: header + batch of N strings.
    Return list of (chunk_text, chunk_metadata).
    """
    header_parts = []
    name_match = re.search(r'(?:private\s+|global\s+)?rule\s+(\w+)', rule_text)
    if name_match:
        header_parts.append(f"Rule: {name_match.group(1)}")

    meta_match = re.search(r'meta\s*:(.*?)(strings\s*:|condition\s*:|$)', rule_text, re.DOTALL | re.IGNORECASE)
    if meta_match:
        for line in meta_match.group(1).split('\n'):
            if '=' in line:
                parts = line.split('=', 1)
                if len(parts) == 2:
                    key = parts[0].strip().lower()
                    val = parts[1].strip().strip('"').strip("'").strip()
                    if key in ['description', 'author', 'date', 'category', 'threat_type', 'malware_type']:
                        header_parts.append(f"{key.capitalize()}: {val[:150]}")

    cond_match = re.search(r'condition\s*:(.*?)(?:\}|$)', rule_text, re.DOTALL | re.IGNORECASE)
    condition = cond_match.group(1).strip() if cond_match else ''
    if condition:
        header_parts.append(f"Condition: {condition[:200]}")

    header = '\n'.join(header_parts)
    yara_strings = extract_yara_strings(rule_text)

    if not yara_strings:
        return [(header, {**base_metadata, 'embed_mode': 'semantic_fallback'})]

    chunks = []
    for i in range(0, len(yara_strings), chunk_size):
        batch = yara_strings[i:i + chunk_size]
        chunk_text = header + '\nStrings:\n' + '\n'.join(f'  {s}' for s in batch)
        chunks.append((chunk_text, {
            **base_metadata,
            'embed_mode': 'chunked_strings',
            'chunk_index': str(i // chunk_size),
            'total_strings': str(len(yara_strings)),
        }))

    return chunks


def embed_text(text):
    """Generate embedding dengan retry untuk transient error"""
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

def format_size(size_bytes):
    """Format ukuran file jadi KB/MB"""
    if size_bytes < 1024:
        return f"{size_bytes}B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes/1024:.1f}KB"
    else:
        return f"{size_bytes/(1024*1024):.1f}MB"

def ingest_yara_folder(docs_path):
    client = chromadb.PersistentClient(path=CHROMA_PATH)
    
    try:
        collection = client.get_collection(COLLECTION_NAME)
        print(f"📂 Collection '{COLLECTION_NAME}' ditemukan.")
    except:
        collection = client.create_collection(COLLECTION_NAME)
        print(f"✨ Collection '{COLLECTION_NAME}' dibuat baru.")

    # Cek existing rules
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
    print(f"✅ Found {len(existing_ids)} rules yang udah ada. Akan skip yang udah ada.\n")

    all_yara_files = []
    for root, _, files in os.walk(docs_path):
        for f in files:
            if f.endswith((".yar", ".yara")):
                all_yara_files.append(os.path.join(root, f))
    
    total_files = len(all_yara_files)
    print(f"🔍 Ditemukan {total_files} file YARA.")
    print(f"⚡ Model: {EMBED_MODEL}")
    print(f"🚀 Mulai proses...\n")

    batch_ids, batch_embeddings, batch_documents, batch_metadatas = [], [], [], []
    total_rules = 0
    skipped_existing = 0
    total_bytes_processed = 0
    start_time = time.time()

    for idx, filepath in enumerate(all_yara_files, 1):
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
                f"New: {total_rules} | Skipped: {skipped_existing} | "
                f"Failed: {len(failed_files)} | "
                f"Processed: {format_size(total_bytes_processed)} | "
                f"ETA: {eta//60:.0f}m{eta%60:.0f}s\n"
            )
            sys.stdout.flush()

        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                raw_content = f.read()
                
            if not re.search(r'rule\s+\w+', raw_content):
                sys.stdout.write(f"\r✅ [{idx}/{total_files}] {filename} ({size_str}) | Skipped (no rules)\n")
                sys.stdout.flush()
                continue

            rules = split_yara_file(raw_content)
            file_rules_processed = 0
            
            for rule_idx, rule_text in enumerate(rules, 1):
                if not rule_text.strip():
                    continue
                
                # Update progress per rule
                sys.stdout.write(f"\r🔄 [{idx}/{total_files}] {filename} ({size_str}) | Rule {rule_idx}/{len(rules)}")
                sys.stdout.flush()
                
                clean_text = clean_yara_text(rule_text)
                if not clean_text:
                    continue
                
                doc_id = generate_unique_id(clean_text)
                if doc_id in existing_ids:
                    skipped_existing += 1
                    continue

                metadata = extract_yara_metadata(clean_text)
                metadata["source"] = filename

                embedding_ok = False
                try:
                    embedding = embed_text(clean_text)
                    embedding_ok = True
                except Exception as e:
                    err = str(e).lower()
                    if "context length" in err or "input length" in err:
                        # Rule terlalu besar — chunk strings ke beberapa embedding
                        for chunk_idx, (chunk_text, chunk_meta) in enumerate(
                            build_yara_chunks(clean_text, dict(metadata))
                        ):
                            chunk_id = generate_unique_id(f"{clean_text}__chunk_{chunk_idx}")
                            if chunk_id in existing_ids:
                                skipped_existing += 1
                                continue
                            try:
                                chunk_emb = embed_text(chunk_text)
                            except Exception as e2:
                                failed_files.append({"path": filepath, "rule": metadata.get("rule_name", "Unknown"), "reason": f"Chunk {chunk_idx} embed error: {str(e2)[:50]}"})
                                continue
                            batch_ids.append(chunk_id)
                            batch_embeddings.append(chunk_emb)
                            batch_documents.append(chunk_text)
                            batch_metadatas.append(chunk_meta)
                            total_rules += 1
                            file_rules_processed += 1
                            if len(batch_ids) >= BATCH_SIZE:
                                collection.upsert(ids=batch_ids, embeddings=batch_embeddings, documents=batch_documents, metadatas=batch_metadatas)
                                batch_ids.clear(); batch_embeddings.clear(); batch_documents.clear(); batch_metadatas.clear()
                    else:
                        failed_files.append({"path": filepath, "rule": metadata.get("rule_name", "Unknown"), "reason": f"Embed: {str(e)[:50]}"})

                if not embedding_ok:
                    continue

                batch_ids.append(doc_id)
                batch_embeddings.append(embedding)
                batch_documents.append(clean_text)
                batch_metadatas.append(metadata)
                total_rules += 1
                file_rules_processed += 1

                if len(batch_ids) >= BATCH_SIZE:
                    collection.upsert(ids=batch_ids, embeddings=batch_embeddings, documents=batch_documents, metadatas=batch_metadatas)
                    batch_ids.clear(); batch_embeddings.clear(); batch_documents.clear(); batch_metadatas.clear()

            total_bytes_processed += file_size
            sys.stdout.write(f"\r✅ [{idx}/{total_files}] {filename} ({size_str}) | Done: {file_rules_processed} rules\n")
            sys.stdout.flush()

        except Exception as e:
            sys.stdout.write(f"\r❌ [{idx}/{total_files}] {filename} ({size_str}) | Error: {str(e)[:50]}\n")
            sys.stdout.flush()
            failed_files.append({"path": filepath, "rule": "FILE_LEVEL", "reason": str(e)[:100]})

    if batch_ids:
        collection.upsert(ids=batch_ids, embeddings=batch_embeddings, documents=batch_documents, metadatas=batch_metadatas)

    elapsed = time.time() - start_time
    print(f"\n{'='*60}")
    print(f"🎉 SELESAI dalam {elapsed//60:.0f}m {elapsed%60:.0f}s")
    print(f"{'='*60}")
    print(f"   ✅ New rules added     : {total_rules}")
    print(f"   ⏭️  Skipped (exist)     : {skipped_existing}")
    print(f"   ❌ Error               : {len(failed_files)}")
    print(f"   📦 Total files         : {total_files}")
    print(f"   💾 Total processed     : {format_size(total_bytes_processed)}")
    print(f"{'='*60}\n")

    if failed_files:
        print(f"❌ ERROR ({len(failed_files)}):")
        for i, err in enumerate(failed_files[:10], 1):
            print(f"{i}. [{err.get('rule', 'N/A')}] {err['path']} -> {err['reason']}")
        
        with open(ERROR_LOG_FILE, "w", encoding="utf-8") as f:
            for err in failed_files:
                f.write(f"{err}\n")
        print(f"\n💾 Full log: {ERROR_LOG_FILE}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ingest YARA rules ke ChromaDB")
    parser.add_argument("--docs", default="./data/rules/rules-master",
                        help="Path ke folder YARA rules (default: ./data/rules/rules-master)")
    args = parser.parse_args()

    if not os.path.exists(args.docs):
        print(f"❌ Folder gak ketemu: {args.docs}")
        print(f"   Jalankan: git clone --depth=1 https://github.com/Yara-Rules/rules data/rules/rules-master")
        exit(1)

    ingest_yara_folder(args.docs)