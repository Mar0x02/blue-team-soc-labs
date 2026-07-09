# AI-RAG Integration — Blue Team SOC Labs

Folder ini berisi pipeline **RAG (Retrieval-Augmented Generation)** yang mengindeks data cybersecurity ke ChromaDB, lalu digunakan Ollama untuk menjawab pertanyaan analisis alert dengan konteks yang kaya.

---

## Struktur Folder

```
AI-Rag-Integration/
├── ingest-thm.py        # Ingest writeup TryHackMe (Markdown/PDF)
├── ingest-yara.py       # Ingest YARA rules (.yar/.yara)
├── ingest-yml.py        # Ingest Sigma rules (.yml/.yaml)
├── ingest-mitre.py      # Ingest MITRE ATT&CK (JSON/STIX)
├── ingest-cve.py        # Ingest CVE database (JSON v5)
├── requirements.txt     # Python dependencies
├── data/                # Folder data source (di-gitignore, clone manual)
│   ├── sigma/           # Clone dari SigmaHQ/sigma
│   ├── rules/           # Clone dari Yara-Rules/rules
│   ├── cvelistV5/       # Clone dari CVEProject/cvelistV5
│   └── cti/             # Clone dari mitre/cti
└── chroma_db/           # Vector database hasil ingest (di-gitignore)
```

---

## Setup Environment

### 1. Buat Virtual Environment

```bash
cd AI-Rag-Integration

python3 -m venv venv

# macOS/Linux
source venv/bin/activate

# Windows
venv\Scripts\activate
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Pastikan Ollama Running

```bash
ollama list

# Agar bisa diakses dari device lain di jaringan
OLLAMA_HOST=0.0.0.0 ollama serve
```

Model yang wajib di-pull:
```bash
ollama pull nomic-embed-text    # Embedding model utama (8192 token context)
```

---

## Clone Data Sources

```bash
mkdir -p data

# 1. Sigma Rules (SigmaHQ)
git clone --depth=1 https://github.com/SigmaHQ/sigma data/sigma

# 2. YARA Rules
git clone --depth=1 https://github.com/Yara-Rules/rules data/rules/rules-master

# 3. MITRE ATT&CK CTI
git clone --depth=1 https://github.com/mitre/cti data/cti/cti-master

# 4. CVE List v5 (besar ~2GB, gunakan filter tahun saat ingest)
git clone --depth=1 https://github.com/CVEProject/cvelistV5 data/cvelistV5
```

> **Catatan:** Folder `data/` dan `chroma_db/` sudah masuk `.gitignore` — tidak ikut ke repo.

---

## Embedding Model

Semua script menggunakan **`nomic-embed-text`** via Ollama.

| Property | Nilai |
|----------|-------|
| Model | `nomic-embed-text` |
| Tokenizer | BERT |
| Context window | 8192 token |
| Ukuran | ~274 MB |
| MAX_EMBED_CHARS | 8000 karakter |

Model ini menggantikan `nomic-embed-text-v2-moe` yang hanya punya 512 token context (T5 tokenizer) — terlalu kecil untuk rules yang panjang.

---

## Fitur Seragam Semua Script

- Progress real-time per file (`[idx/total] filename | status`)
- Summary tiap 50 file: elapsed time + ETA + jumlah data terproses
- **Skip otomatis** untuk data yang sudah ada di ChromaDB (resume-friendly)
- Error per file dicatat tanpa menghentikan proses keseluruhan
- Error log tersimpan ke file `.log` untuk investigasi manual
- **Paginated ID loading**: Saat cek existing data, `collection.get()` dipanggil batch per 5000 entry untuk menghindari `too many SQL variables` error pada ChromaDB (SQLite backend)

### Dedup & Resume

Setiap script mengecek existing data di database sebelum mulai proses. Jika doc ID sudah ada, file/rule/entry tersebut di-skip. Aman dijalankan ulang setelah proses terputus — tidak akan ada duplikasi.

### Mode Jalankan

**Auto-scan** — scan folder default `./data/` tanpa argumen:
```bash
python ingest-yml.py
```

**Manual path** — tentukan folder spesifik:
```bash
python ingest-yml.py --docs data/sigma/rules/windows
```

---

## Script Ingest

---

### `ingest-thm.py` — TryHackMe Writeups

Ingest dokumen Markdown dan PDF dari writeup TryHackMe personal.

```bash
# Wajib tentukan path folder writeup
python ingest-thm.py --docs /path/to/thm-writeups
```

**Format yang didukung:** `.md`, `.txt`, `.pdf`

**Yang di-extract:**

| Field | Keterangan |
|-------|------------|
| `source` | Nama file asal |
| `chunk` | Nomor chunk |
| `type` | `thm_writeup` |

**Cara kerja:**

Setiap dokumen dipecah menjadi chunks (1500 karakter, overlap 150) lalu masing-masing chunk di-embed ke ChromaDB. Overlap 150 karakter dipakai karena konten writeup adalah prosa naratif — kalimat bisa terpotong di tengah boundary, overlap menjaga konteks tetap utuh. PDF dibaca per halaman menggunakan `pypdf`.

Doc ID berbasis `MD5(absolute_path + chunk_index)` — unik per chunk per file.

---

### `ingest-yara.py` — YARA Rules

Ingest YARA rules dari repo [Yara-Rules/rules](https://github.com/Yara-Rules/rules).

```bash
# Auto-scan ke ./data/rules/rules-master
python ingest-yara.py

# Manual — scan subfolder spesifik
python ingest-yara.py --docs data/rules/rules-master/malware
python ingest-yara.py --docs data/rules/rules-master/antidebug_antivm
```

**Format yang didukung:** `.yar`, `.yara`

**Yang di-extract:**

| Field | Keterangan |
|-------|------------|
| `type` | `yara_rule` |
| `rule_name` | Nama rule YARA |
| `description` | Deskripsi rule (dari blok `meta`) |
| `author` | Author rule |
| `date` | Tanggal pembuatan rule |
| `hash` / `md5` / `sha256` | Hash sample yang terkait |
| `severity` | Tingkat keparahan |
| `category` | Kategori malware |
| `threat_type` / `malware_type` | Tipe ancaman |
| `reference` | Referensi eksternal |
| `has_hex_strings` | Ada hex pattern di strings section |
| `has_text_strings` | Ada text pattern di strings section |
| `source` | Nama file asal |
| `embed_mode` | `full` / `chunked_strings` / `semantic_fallback` |

**Cara kerja:**

1. Setiap file YARA bisa berisi banyak rule — script memisahkan per rule dengan brace-tracking (`{}`).
2. Komentar dihapus (`/* */` dan `//`) sebelum diproses.
3. Doc ID berbasis `MD5(clean_rule_text)` — dedup berbasis konten.
4. **Reactive chunking untuk rule besar**: Script pertama mencoba embed full rule text. Jika gagal karena "context length exceeded":
   - Extract semua string definitions dari blok `strings:` (baris yang diawali `$` dan mengandung `=`)
   - Buat header: nama rule + meta (description, author, date, category) + condition
   - Pecah strings jadi batch 25 per chunk
   - Setiap chunk = header + 25 strings → di-embed terpisah
   - Chunk ID: `MD5(clean_text + "__chunk_N")`

   Tidak ada overlap antar chunk strings — setiap string definition independen, tidak ada konteks yang hilang.

5. Kalau rule tidak punya strings section → embed header saja dengan `embed_mode: semantic_fallback`.

---

### `ingest-yml.py` — Sigma Rules

Ingest Sigma detection rules dari repo [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma).

```bash
# Auto-scan ke ./data/sigma/rules
python ingest-yml.py

# Manual — scan platform spesifik
python ingest-yml.py --docs data/sigma/rules/windows
python ingest-yml.py --docs data/sigma/rules/linux
python ingest-yml.py --docs data/sigma/rules/cloud
```

**Format yang didukung:** `.yml`, `.yaml`

Rule dengan status `deprecated` atau `unsupported` di-skip otomatis.

**Yang di-extract:**

| Field | Keterangan |
|-------|------------|
| `type` | `sigma_rule` |
| `title` | Judul rule |
| `description` | Deskripsi deteksi (maks 500 char) |
| `level` | Severity: `informational`, `low`, `medium`, `high`, `critical` |
| `status` | Status rule |
| `tags` | MITRE ATT&CK tags (misal: `attack.t1059`) |
| `log_product` | Platform log: `windows`, `linux`, `aws`, dll |
| `log_category` | Kategori log: `process_creation`, `network`, dll |
| `event_ids` | Windows Event ID yang relevan |
| `process_names` | Nama proses yang dimonitor |
| `target_files` | File yang menjadi target |
| `command_patterns` | Pola command line yang dicurigai |
| `source` | Nama file asal |
| `path` | Subfolder dalam repo Sigma |
| `embed_mode` | `full` / `chunked_indicators` |

**Cara kerja:**

1. Satu file YAML bisa berisi beberapa dokumen (multi-document YAML via `yaml.safe_load_all`).
2. Field teknis diekstrak dari blok `detection` secara rekursif (event IDs, proses, file, command patterns).
3. Doc ID berbasis `MD5(filepath__rule_index)` — stabil, tidak berubah meski konten diupdate minor.
4. **Reactive chunking untuk indicator list rules**: Beberapa Sigma rules berisi ratusan indikator di blok `detection` (driver hashes, domain lists, PowerShell commandlets). Script mencoba embed `yaml.dump(doc)` dulu. Jika gagal karena "context length exceeded":
   - Rekursif ekstrak semua nilai string/int dari seluruh blok detection (kecuali field `condition`)
   - Buat header: title + description + tags + level + logsource
   - Pecah indikator jadi batch 30 per chunk
   - Setiap chunk = header + 30 indikator → di-embed terpisah
   - Chunk ID: `MD5(filepath__rule_idx__chunk_N)`

   Tidak ada overlap — setiap indikator (hash, domain, commandlet) adalah entri independen; header di-repeat di tiap chunk sebagai konteks.

---

### `ingest-mitre.py` — MITRE ATT&CK

Ingest MITRE ATT&CK framework dari repo [mitre/cti](https://github.com/mitre/cti).

```bash
# Auto-scan ke ./data/cti/cti-master/enterprise-attack
python ingest-mitre.py

# Manual — pilih domain ATT&CK spesifik
python ingest-mitre.py --docs data/cti/cti-master/enterprise-attack
python ingest-mitre.py --docs data/cti/cti-master/mobile-attack
python ingest-mitre.py --docs data/cti/cti-master/ics-attack
```

**Format yang didukung:** `.json` (STIX bundle)

**Yang di-extract:**

| Field | Keterangan |
|-------|------------|
| `type` | `mitre_attack` |
| `object_type` | Tipe STIX: `attack-pattern`, `course-of-action`, `intrusion-set`, `malware`, `tool` |
| `stix_id` | ID unik STIX object |
| `name` | Nama teknik/grup/malware |
| `description` | Deskripsi lengkap (maks 500 char) |
| `technique_id` | ID teknik ATT&CK (misal: `T1059.001`) |
| `tactics` | Taktik: `execution`, `persistence`, `lateral-movement`, dll |
| `platforms` | Platform target: `Windows`, `Linux`, `macOS`, dll |
| `data_sources` | Sumber data untuk deteksi |
| `detection` | Panduan deteksi (maks 300 char) |
| `mitigation_id` | ID mitigasi (untuk `course-of-action`) |
| `group_id` | ID grup APT (untuk `intrusion-set`) |
| `aliases` | Nama alias grup (maks 5) |
| `software_id` | ID software (untuk `malware`/`tool`) |
| `source` | Nama file JSON asal |

**Cara kerja:**

File JSON MITRE bisa berformat bundle (`{"objects": [...]}`) atau array langsung — script detect otomatis. Object dengan `revoked: true` atau `x_mitre_deprecated: true` di-skip. Doc ID berbasis `MD5(stix_id)` — stabil mengikuti STIX object ID. Tidak perlu chunking karena description sudah dibatasi 500 char, total teks per object ~600-700 char.

Tipe STIX yang di-skip: `relationship`, `x-mitre-matrix`, `x-mitre-tactic`, `marking-definition`, `identity`.

---

### `ingest-cve.py` — CVE Database

Ingest CVE database dari repo [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5). Hanya memproses CVE dengan state `PUBLISHED`.

```bash
# Filter tahun range (disarankan)
python ingest-cve.py --docs data/cvelistV5/cves --year-from 2022 --year-to 2026

# Hanya dari tahun tertentu ke atas
python ingest-cve.py --docs data/cvelistV5/cves --year-from 2024

# Filter severity minimum
python ingest-cve.py --docs data/cvelistV5/cves --year-from 2024 --min-severity HIGH
python ingest-cve.py --docs data/cvelistV5/cves --year-from 2024 --min-severity CRITICAL

# Auto-scan semua CVE (300k+ file, sangat lama)
python ingest-cve.py
```

**Format yang didukung:** `.json` (CVE JSON v5, nama file harus diawali `CVE-`)

**Filter tahun**: Tahun diambil dari nama file CVE (`CVE-YYYY-XXXXX`) menggunakan regex — tidak baca isi JSON dulu, jadi filter cepat.

**Yang di-extract:**

| Field | Keterangan |
|-------|------------|
| `type` | `cve_entry` |
| `cve_id` | ID CVE (misal: `CVE-2024-1234`) |
| `description` | Deskripsi kerentanan (maks 500 char) |
| `date_published` | Tanggal publikasi (`YYYY-MM-DD`) |
| `cvss_score` | Skor CVSS (prioritas: v3.1 > v3.0 > v2.0) |
| `cvss_severity` | Tingkat: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| `attack_vector` | Vektor serangan dari CVSS: `NETWORK`, `LOCAL`, `ADJACENT`, dll |
| `privileges_required` | Hak akses yang dibutuhkan: `NONE`, `LOW`, `HIGH` |
| `cwe_ids` | ID CWE kelemahan (maks 3) |
| `capec_ids` | ID CAPEC attack pattern dari `cna.impacts` |
| `affected_products` | Produk yang terdampak: `vendor product` (maks 5) |
| `affected_versions` | Versi yang terdampak (maks 5, dari `cna.affected`) |
| `exploitation_status` | Status eksploitasi aktif dari CISA SSVC (`adp.metrics.ssvc`) |
| `solution` | Solusi/mitigasi dari CNA (maks 300 char) |
| `references` | URL referensi (maks 5) |
| `source` | Nama file JSON asal |

**Cara kerja:**

1. Format JSON: `cveMetadata` (ID, state, tanggal) + `containers.cna` (deskripsi, CVSS, CWE, produk, solusi) + `containers.adp` (CISA SSVC exploitation status).
2. Doc ID berbasis `MD5(cve_id)` — stabil. Re-run dengan enrichment tambahan tidak akan membuat entry baru selama CVE ID sama.
3. Embed text menyertakan semua field di atas dalam format human-readable agar retrieval semantik efektif.
4. Jika embed text gagal karena context length, fallback ke teks minimal: `CVE ID + description[:500] + CVSS + affected_products[:200]`.
5. `product` yang terlalu panjang (>80 char, biasanya comma-separated list model numbers) dipotong ke model pertama saja.

---

## Requirements

```
chromadb>=0.5.0
ollama>=0.3.0
pyyaml>=6.0
pypdf>=4.0.0
```

---

## Urutan Ingest yang Disarankan

```bash
# 1. MITRE ATT&CK — fondasi konteks TTP, paling kecil dan cepat
python ingest-mitre.py

# 2. Sigma Rules — detection rules, ribuan file
python ingest-yml.py

# 3. YARA Rules — malware signatures
python ingest-yara.py

# 4. CVE — range 2022-2026 tanpa severity filter (~171K entries)
python ingest-cve.py --docs data/cvelistV5/cves --year-from 2022 --year-to 2026

# 5. THM Writeups — personal knowledge base, wajib tentukan path
python ingest-thm.py --docs /path/to/thm-writeups
```

> **Tips:** Semua script mendukung **resume** — kalau proses terputus, tinggal jalankan ulang. Data yang sudah ada di database akan di-skip otomatis.

---

## Error Log & Retry

Setiap script menyimpan file yang gagal ke log masing-masing:

| Script | Log File |
|--------|----------|
| `ingest-thm.py` | `ingest_thm_errors.log` |
| `ingest-yara.py` | `ingest_yara_errors.log` |
| `ingest-yml.py` | `ingest_yml_errors.log` |
| `ingest-mitre.py` | `ingest_mitre_errors.log` |
| `ingest-cve.py` | `ingest_cve_errors.log` |

Log berisi path lengkap dan alasan error untuk setiap entry yang gagal.

---

## Catatan Teknis: Reactive Chunking

Sigma dan YARA punya pola khusus — beberapa rules punya ratusan indikator (driver hashes, domain list, AV engine names, hex opcodes). Script menggunakan **reactive chunking**: tidak ada pre-emptive splitting berdasarkan ukuran file; embed dicoba dulu pada full text, chunking hanya terjadi kalau Ollama melempar error "input length exceeds context length".

Ini penting karena:
- Sebagian besar rules normal (<8192 token) — tidak perlu chunking, satu embedding = satu rule = retrieval lebih presisi
- Hanya rules anomali (biasanya aggregated threat intel lists) yang kena chunking
- Rules lama yang sudah masuk database tidak terpengaruh — doc ID berbeda antara full-rule dan chunked mode

Indikator list tidak butuh overlap karena setiap indikator berdiri sendiri; header di-repeat di tiap chunk untuk menjaga konteks (nama rule, level, logsource/category).
