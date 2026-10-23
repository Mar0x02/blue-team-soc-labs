# 🧱 Tahap 5 — SecRule Tulisan Sendiri + Anomaly Scoring & Paranoia

> **Status:** ✅ **LIVE 2026-10-23** — SQLi & XSS custom rule jalan, anomaly scoring (PL1 block) + paranoia gating (PL2 detection-only) kebukti via adu payload. Docker **sama persis** dengan [Tahap 3](./03-modsecurity-build.md) — tahap ini **murni nambah rule** di atas engine yang udah jadi, gak ada build/compose baru. Bagian dari [ModSecurity build from scratch](./README.md), nyakup roadmap Tahap 5–6.

## Tujuan

Nulis **SecRule sendiri tanpa CRS**, dan ngerti cara kerja **anomaly scoring** + **paranoia level** dari dalam:

1. **Anatomi SecRule** — variable, operator, transformation, action, phase
2. **Anomaly model** — rule deteksi cuma *nyumbang skor*, satu rule eval yang *mutusin block*
3. **Paranoia level** — misahin rule yang **nge-block** (high confidence) vs yang **cuma log** (shadow / lagi dituning), lewat `blocking_paranoia_level` vs `detection_paranoia_level` + gerbang `skipAfter`

Payload yang **lolos di Tahap 2** (regex native nginx) jadi bahan uji: libinjection `@detectSQLi`/`@detectXSS` harusnya nangkep yang regex mentah lolosin.

| Komponen | Nilai | Catatan |
|----------|-------|---------|
| Engine | `SecRuleEngine On` | Dari Tahap 3 Iterasi 2 |
| Range rule custom | `100000–199999` | Hindari range CRS `900000–999999` |
| Critical anomaly score | `5` | Threshold inbound `5` → 1 hit critical = block |
| Paranoia | blocking `1`, detection `2` | PL1 nge-block, PL2 cuma log |

---

## Prerequisites

- **Tahap 3 selesai** ([`03-modsecurity-build.md`](./03-modsecurity-build.md)) — engine ModSecurity udah nyala, `main.conf` + audit log JSON jalan.
- **Docker gak berubah.** Tahap ini cuma ngedit/nambah file di `conf/nginx/modsec/` (dibaca via mount yang udah ada). Deploy = sync file + `--force-recreate`, **gak rebuild image**.

---

## Konsep: 4 peran di model anomaly

Biar gak ketuker, tiap baris di config punya peran beda:

| Peran | Wujud | Fungsi |
|-------|-------|--------|
| **Init** | `SecAction` (id `100900`) | Bikin ember skor + set threshold & paranoia level |
| **Rule deteksi** | `SecRule ... @detectSQLi` dll | Match serangan → **ngisi ember** skor + log |
| **Gerbang** | `SecRule TX:DETECTION_PARANOIA_LEVEL ... skipAfter` | Nentuin grup rule PL2 **jalan apa nggak** |
| **Keputusan** | `SecRule TX:INBOUND_ANOMALY_SCORE_PL1 ... deny` (id `100999`) | **Baca ember** → `deny` kalau ≥ threshold |

**`block` ≠ pasti block.** `block` artinya "ikut `SecDefaultAction`". Karena `SecDefaultAction phase:2` = `pass`, rule deteksi yang `block` itu **gak nge-block sendiri** — cuma nyumbang skor; yang beneran `deny` cuma `100999`. Rule yang mau murni log pakai **`pass`** (dijamin gak block apapun mode-nya).

---

## Step-by-Step

### 1. Engine config + init (`conf/nginx/modsec/main.conf`)

`main.conf` ngatur engine, audit log, inisialisasi skor, lalu `Include` semua file rule, terus rule keputusan.

```
SecRuleEngine On

SecAuditEngine RelevantOnly
SecAuditLog /var/log/nginx/modsec/modsec_audit.log
SecAuditLogFormat JSON
SecAuditLogRelevantStatus "^(?:5|4(?!04))"
SecRequestBodyAccess On

SecDefaultAction "phase:1,pass,log,auditlog"
SecDefaultAction "phase:2,pass,log,auditlog"

SecAction "id:100900,phase:1,pass,nolog,t:none, \
    setvar:tx.critical_anomaly_score=5, \
    setvar:tx.inbound_anomaly_score_threshold=5, \
    setvar:tx.inbound_anomaly_score_pl1=0, \
    setvar:tx.inbound_anomaly_score_pl2=0, \
    setvar:tx.blocking_paranoia_level=1, \
    setvar:tx.detection_paranoia_level=2"

Include /etc/nginx/modsec/rules/*.conf

SecRule TX:INBOUND_ANOMALY_SCORE_PL1 "@ge %{tx.inbound_anomaly_score_threshold}" \
    "id:100999,phase:2,deny,status:403,log, \
    msg:'Inbound Anomaly Score Exceeded (score %{tx.inbound_anomaly_score_pl1})'"
```

| Directive | Fungsi |
|-----------|--------|
| `SecAuditLogRelevantStatus "^(?:5\|4(?!04))"` | Audit cuma 4xx/5xx (kecuali 404). Tapi rule yang match dengan `auditlog` bikin transaksinya "relevant" → **tetap keaudit walau 200** |
| `SecDefaultAction phase:2 pass` | Default non-disruptif → `block` di rule = `pass` (mode anomaly) |
| `100900` init | Ember `pl1`/`pl2` di-nol-in; threshold inbound `5`; blocking `1`, detection `2` |
| `100999` keputusan | **Satu-satunya** yang `deny`. Baca `pl1` doang → cuma PL1 yang bisa nge-block |

### 2. Rule PL1 — produksi, nge-block (`rules/rules-sqli.conf`, `rules/rules-xss.conf`)

Rule **high confidence** pakai libinjection. Nyumbang ke ember `pl1` → ditegakin `100999`.

`rules/rules-sqli.conf`:
```
SecRule ARGS,ARGS_NAMES,REQUEST_HEADERS,REQUEST_BODY,REQUEST_HEADERS:User-Agent "@detectSQLi" \
    "id:100001, \
    phase:2, \
    block, \
    nolog, \
    auditlog, \
    status:403, \
    t:none,t:urlDecodeUni,t:lowercase, \
    msg:'SQL Injection Attack Detected', \
    severity:CRITICAL, \
    tag:'paranoia-level/1', \
    tag:'attack-sqli', \
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
```

`rules/rules-xss.conf` — `@detectXSS` (libinjection), pola sama, ember `pl1`, tag `paranoia-level/1`, id `100002`.

| Bagian | Arti |
|--------|------|
| `ARGS,ARGS_NAMES,...` | Variable: di mana nyari (query, nama arg, body, User-Agent) |
| `@detectSQLi` / `@detectXSS` | Operator libinjection — jauh lebih akurat dari regex mentah Tahap 2 |
| `t:urlDecodeUni,t:lowercase` | Transformation: decode + normalisasi **sebelum** dicek (Tahap 2 gagal karena `$args` gak di-decode) |
| `block` + `setvar pl1` | Nyumbang skor ke ember PL1 (block via `100999`) |

### 3. Rule PL2 — shadow / tuning (`rules/tune-rules.conf`)

Rule yang **masih dituning / rawan false positive** ditaruh di sini, dibungkus **gerbang** + ember `pl2`. Karena `100999` cuma baca `pl1`, PL2 **cuma ke-log, gak block** (shadow mode).

```
SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 2" \
    "id:100901,phase:2,pass,nolog,skipAfter:END-PL2"

SecRule ARGS,REQUEST_BODY "@rx (?i)(?:<script|<img|<iframe|<object|<embed|<applet|<meta|<style|<link|<base|<form|<input|<textarea|<button|<select|<option|<label|<fieldset|<legend|<datalist|<keygen|<output|<progress|<meter|<details|<summary|<menuitem|<menu)\b" \
    "id:100003, \
    phase:2, \
    pass, \
    nolog, \
    auditlog, \
    t:none,t:urlDecodeUni,t:lowercase,t:htmlEntityDecode, \
    msg:'Cross-Site Scripting (XSS) Attack Detected', \
    severity:CRITICAL, \
    tag:'paranoia-level/2', \
    tag:'attack-xss', \
    setvar:'tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}'"

SecMarker END-PL2
```

- **Gerbang** (`100901`): kalau `detection_paranoia_level < 2` → `skipAfter:END-PL2` (lompat ke marker, lewatin semua PL2). Sekarang detection = `2` → `2 @lt 2` = false → gerbang gak aktif → PL2 jalan.
- **`pass`**: PL2 ini detection-only, gak boleh block sendiri.
- **`setvar pl2`**: nuang skor ke ember **PL2** (bukan PL1) → gak keitung `100999`.
- Regex taglist sengaja **noisy** (match `<form>`, `<input>`, `<label>` yang legit) → makanya cocok di shadow dulu, bukan langsung block.

### 4. Kenapa dipisah 3 file + urutan load

`Include /etc/nginx/modsec/rules/*.conf` baca file **urut alfabetis**:

```
rules-sqli.conf   → 100001 (PL1)
rules-xss.conf    → 100002 (PL1)
tune-rules.conf   → 100901 gerbang → 100003 (PL2) → END-PL2
```

`r` < `t`, jadi `tune-rules.conf` **ke-load terakhir** → gerbang otomatis ada **setelah semua rule PL1**. Ini penting: gerbang `skipAfter:END-PL2` cuma boleh ngebungkus rule PL2. Kalau rule PL1 kejepit di antara gerbang & marker, dia ikut ke-skip pas `detection=1` — padahal PL1 harus selalu jalan.

> Aturan: file rule PL1 produksi = `rules-*.conf`. Rule PL2 yang dituning = dalam `tune-rules.conf`, di antara gerbang & `END-PL2`.

### 5. Deploy (docker sama Tahap 3)

```bash
# dari Mac — sync file rule yang berubah
scp -r conf/nginx/modsec anang@10.10.10.5:/data/waf/scratch/conf/nginx/

# di VM
cd /data/waf/scratch
mkdir -p logs/modsec && sudo chown 101:101 logs/modsec && sudo chmod 750 logs/modsec
docker compose up -d --force-recreate     # gak rebuild, cuma recreate container
docker exec waf-scratch nginx -t
```

---

## Verifikasi — Live 2026-10-23

Test dari Mac (Firefox, `192.168.43.193`) ke DVWA via WAF `192.168.43.100`.

### 1. PL1 nge-block (anomaly chain)

| Payload | Hasil | Rule |
|---------|-------|------|
| SQLi `id=1' OR '1'='1` | **403** | `100001` detect → `pl1`+5 → `100999` deny |
| XSS `<script>alert(1)</script>` | **403** | `100002` detect → `pl1`+5 → `100999` deny |

![XSS `<script>` → 403 (PL1 block)](../asset/modsecurity-scratch/tahap-3-xss-detectxss-pl1-403.png)

Audit log XSS `<script>` nangkep **1 entri, 3 message** — jejak chain lengkap: `100002` (pl1) + `100003` (pl2, ikut match) + `100999` (keputusan deny). Yang bikin block = PL1; PL2 cuma nebeng log.

### 2. PL2 detection-only (shadow) — kebukti isolasi

Payload yang **match regex taglist tapi LOLOS libinjection**: `name=<form>`.

| Payload | Hasil | Rule |
|---------|-------|------|
| `name=<form>` | **200** (halaman DVWA kebuka normal) | cuma `100003` (pl2) → `100999` gak baca pl2 → **log doang, gak block** |

![`<form>` → 200, PL2 cuma ke-log](../asset/modsecurity-scratch/tahap-3-xss-form-pl2-detection-200.png)

Audit log `<form>` cuma **1 message**: `ruleId 100003` tag `paranoia-level/2`, `is_interrupted: false`, `http_code 200`. **Gak ada** `100002` (libinjection bener, `<form>` bukan XSS) & **gak ada** `100999`. Inilah bukti murni **detection ≠ blocking**.

### Ringkasan bukti

| | PL1 (`@detectXSS`) | PL2 (`@rx` taglist) |
|---|---|---|
| Ember | `pl1` | `pl2` |
| Dibaca `100999`? | ✅ ya | ❌ nggak |
| `<script>alert(1)</script>` | **403** | ikut log |
| `<form>` | gak match | **200 + log doang** |

---

## Catatan & Batasan (buat tahap lanjut)

- **Promote PL2 → blocking**: ubah `100999` biar ikut jumlahin `pl2` kalau `blocking_paranoia_level ≥ 2` (atau tambah eval per-PL). Rule PL2-nya tetap `pass` — yang nge-block tetap si eval. Belum dikerjain.
- **Paranoia gating penuh (PL3–4)**: tiap level di atas PL1 butuh gerbang + marker sendiri (`@lt N`). Sekarang baru PL2.
- **Outbound**: `SecResponseBodyAccess` + rule outbound belum ada (threshold di-set tapi belum dipakai).
- **Rule high-confidence (direct `deny`)**: path traversal / sensitive path lebih cocok `deny` langsung (sekali match = pasti jahat, gak perlu scoring) — rencana berikutnya.
