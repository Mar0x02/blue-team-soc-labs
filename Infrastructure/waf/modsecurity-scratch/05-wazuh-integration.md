# 🛰️ Tahap 5 — Integrasi Wazuh (Forward `modsec_audit.log` → SIEM)

> **Status:** 🚧 **LIVE (progres)** — audit log ModSec (JSON) di-forward dari VM `waf` ke Wazuh Manager (Dell) lewat `<localfile>`; rule `100700`–`100704` fire live 2026-10-30 buat Command Injection (`100702`), SQLi (`100703`), XSS (`100704`), semua mapping **MITRE T1190**, source IP attacker (Kali `192.168.43.63`) kebaca bener. Docker WAF **gak berubah** dari [Tahap 4](./04-modsecurity-basic-rules.md) — tahap ini kerja di sisi **agent** (config `<localfile>`) + **Manager** (rule), plus satu tweak kecil di `main.conf` (rampingin audit log). Bagian dari [ModSecurity build from scratch](./README.md), nyakup roadmap Tahap 5.

## Tujuan

Nyambungin WAF ke SOC: tiap request yang **diblok ModSecurity** harus muncul jadi **alert di Wazuh**, dengan field yang berguna buat analis (source IP, URI, kategori serangan, MITRE). Fokus **detection**, bukan prevention — WAF-nya udah nge-block, di sini mastiin block-nya **kelihatan** di SIEM.

Yang dipelajari:

1. **Forward log JSON** ke Wazuh lewat `<localfile>` (`log_format json`) — gak perlu decoder custom, JSON decoder bawaan yang kerja.
2. **Keterbatasan JSON decoder** soal array of objects — `messages[]` jadi **satu blob string**, nentuin cara nulis rule.
3. **Rule hierarki** (base → blocked → kategori) yang **nembak field hasil decode**, didesain reusable.

| Komponen | Nilai | Catatan |
|----------|-------|---------|
| Sumber log | `/data/waf/scratch/logs/modsec/modsec_audit.log` | JSON serial (1 objek per baris) |
| Agent | `waf` (id `006`, ip `10.10.10.5`) | VM WAF, di-enroll ke Manager Dell |
| Manager | Wazuh `4.13.1` (Dell) | Indexer + Dashboard |
| Decoder | `json` (bawaan) | Gak ada decoder XML custom |
| Rule custom | `100700`–`100704` | [`Detection-Engineer/wazuh/rule/waf_rules.xml`](../../../Detection-Engineer/wazuh/rule/waf_rules.xml) |
| Range rule | `100700+` | Lab Wazuh rule lain kepake sampe `100610` |

---

## Prerequisites

- **Tahap 4 selesai** ([`04-modsecurity-basic-rules.md`](./04-modsecurity-basic-rules.md)) — ModSecurity udah nge-block + nulis audit log JSON (`SecAuditLogFormat JSON`, `SecAuditLogType Serial`).
- **Wazuh Agent** udah keinstall di VM `waf` dan ke-enroll ke Manager (Dell). Audit log ke-mount ke host (`./logs:/var/log/nginx` di compose), jadi agent baca dari host — **gak perlu** agent di dalem container.
- **Wazuh Manager** (Dell) jalan, Dashboard kebuka.
- **Kali** (`192.168.43.63`) sebagai attacker eksternal buat validasi.

---

## Arsitektur

```
Kali (192.168.43.63) ──serangan──> WAF (192.168.43.100) ──block 403──> modsec_audit.log (JSON)
                                                                             │
                                                        Wazuh Agent (VM waf) ─┤ <localfile> json
                                                                             ▼
                                                        Wazuh Manager (Dell) ── JSON decoder ── rule 100700-100704 ── ALERT
```

---

## Step-by-Step

### 1. Sumber log — `modsec_audit.log` (JSON serial)

Dari Tahap 4, `main.conf` udah nulis audit log JSON:

```
SecAuditEngine RelevantOnly
SecAuditLog /var/log/nginx/modsec/modsec_audit.log
SecAuditLogFormat JSON
SecAuditLogType Serial
SecAuditLogRelevantStatus "^(?:5|4(?!04))"
```

- **`RelevantOnly` + `RelevantStatus`** → cuma nyatet response 4xx/5xx (kecuali 404). Jadi yang masuk log = request yang **diblok (403)** atau error server — udah ke-filter di sumber, sinyal bersih.
- **`Serial`** → semua transaksi masuk **satu file**, **satu objek JSON per baris**. Ini yang kompatibel sama `log_format json` Wazuh.

### 2. Rampingin audit log — buang response body (`SecAuditLogParts`)

Audit part default (`ABIJDEFHZ`) termasuk **`E` = response body**. Karena tiap request yang diblok dikasih halaman error custom (lihat [`403.html`](./conf/nginx/html/403.html)), **seluruh body HTML (~4.6 KB) ikut masuk tiap entri audit** — bikin log membengkak, dan berisiko kena limit ukuran event Wazuh → JSON ke-truncate → gagal decode.

Buang part `E`:

```
SecAuditLogParts ABIJDEFHZ   →   SecAuditLogParts ABIJDFHZ
```

Part yang disimpen: `A` (header audit), `B` (request headers), `F` (response headers), `H` (trailer — **ini yang isinya `messages[]`/rule match, wajib ada**), `Z` (penutup). Setelah `--force-recreate`, entri audit jadi ramping (gak ada `response.body` lagi).

### 3. Forward via agent — `<localfile>` di VM `waf`

Tambahin di `/var/ossec/etc/ossec.conf` (sisi agent, VM `waf`):

```xml
<localfile>
  <log_format>json</log_format>
  <location>/data/waf/scratch/logs/modsec/modsec_audit.log</location>
</localfile>
```

- **`log_format json`** → logcollector baca tiap baris sebagai objek JSON utuh.
- **Permission**: folder `logs/modsec/` owner uid `101` (nginx) mode `750`, tapi logcollector jalan **as root** → tetap kebaca (root bypass).

Restart agent:

```bash
sudo systemctl restart wazuh-agent
```

### 4. Decoder — gak perlu custom

Karena `log_format json`, **JSON decoder bawaan Wazuh** otomatis nge-flatten tiap objek jadi field dot-notation (`transaction.client_ip`, `transaction.response.http_code`, dst). **Gak perlu nulis decoder XML** kayak accesslog plain text.

> ⚠️ **Gotcha penting — array of objects jadi blob.** JSON decoder nge-flatten objek bersarang, **tapi array of objects enggak**. Field `messages` itu array; Wazuh nyimpen **seluruh array sebagai satu string** di `transaction.messages`, **bukan** `transaction.messages[].details.tags`. Jadi field kayak `transaction.messages.details.ruleId` **gak eksis**. Konsekuensinya: kategori serangan di-match lewat **substring ke blob `transaction.messages`** (lihat Step 5), bukan ke field bersarang. Ini malah **lebih tahan banting** — walau 1 request match banyak rule (blob gabungin semua tag), substring tetap nangkep.

### 5. Rule deteksi — [`waf_rules.xml`](../../../Detection-Engineer/wazuh/rule/waf_rules.xml)

Ditaruh di Manager (`/var/ossec/etc/rules/`). Hierarki **base → blocked → kategori**:

```xml
<group name="modsecurity,waf,">

  <!-- BASE: anchor semua event audit ModSec (level 0 = induk, gak alert) -->
  <rule id="100700" level="0">
    <decoded_as>json</decoded_as>
    <field name="transaction.producer.modsecurity">\.+</field>
    <description>ModSecurity: audit event</description>
  </rule>

  <!-- BLOCKED: is_interrupted=true → request ditolak WAF. Inti alert, jalan buat custom DAN CRS -->
  <rule id="100701" level="7">
    <if_sid>100700</if_sid>
    <field name="transaction.is_interrupted">true</field>
    <description>WAF: request diblokir ModSecurity ($(transaction.request.method) $(transaction.request.uri)) dari $(transaction.client_ip)</description>
    <mitre><id>T1190</id></mitre>
    <group>attack,blocked,</group>
  </rule>

  <!-- KATEGORI: match substring tag ke blob transaction.messages -->
  <rule id="100702" level="10">
    <if_sid>100701</if_sid>
    <field name="transaction.messages">attack-command-injection</field>
    <description>WAF: Command Injection diblokir dari $(transaction.client_ip)</description>
    <mitre><id>T1190</id></mitre>
  </rule>
  <!-- 100703 → attack-sqli ; 100704 → attack-xss (pola sama) -->

</group>
```

Keputusan desain:

| Keputusan | Alasan |
|-----------|--------|
| Kategori by **`tags`** (bukan `ruleId`) | Tahan array/multi-match; `tags` di blob tetap ke-substring walau messages banyak |
| Sinyal blocked = **`is_interrupted:true`** | Pasti nandain ModSec yang nolak, bukan 403 dari backend |
| Mapping **`T1190`** | *Exploit Public-Facing Application* — ATT&CK yang pas buat serangan di perimeter web |
| Level: base `0`, blocked `7`, kategori `10` | Induk senyap, blocked generik, kategori spesifik = actionable |

---

## Verifikasi

### 1. `wazuh-logtest` — decode & rule fire

Paste 1 baris audit ke `sudo /var/ossec/bin/wazuh-logtest`. Potongan **Phase 2** yang penting:

```
transaction.client_ip: '192.168.43.63'
transaction.is_interrupted: 'true'
transaction.response.http_code: '403'
transaction.request.uri: '/vulnerabilities/exec/'
transaction.messages: '[{'message': 'Command Injection...', 'details': {... 'tags': ['paranoia-level/1', 'attack-command-injection'], ...}}]'   ← SATU blob string
```

`transaction.messages` keluar sebagai **satu string** (bukan field bersarang) — persis gotcha di Step 4. **Phase 3** fire `100702` level `10`, mapping `T1190` / *Initial Access*.

### 2. Matriks serangan dari Kali

Serangan dari Kali (`192.168.43.63`) ke DVWA via WAF (`192.168.43.100`):

| Kategori | Payload | WAF | ModSec rule | **Wazuh rule.id** | Level |
|----------|---------|-----|-------------|-------------------|-------|
| Command Injection | `;whoami` | **403** | `100005` deny | **`100702`** | 10 |
| Command Injection | `\|id` | **403** | `100005` deny | **`100702`** | 10 |
| SQL Injection | `1' ORDER BY 1-- -` | **403** | `100001` detect → `100999` deny | **`100703`** | 10 |
| SQL Injection | `1' OR 1=1` | **403** | `100001` detect → `100999` deny | **`100703`** | 10 |
| XSS | `<script>alert(1)</script>` | **403** | `100002`+`100003` → `100999` deny | **`100704`** | 10 |
| **Normal (negatif)** | `GET /login.php` | **200** | — | **gak ada alert** ✅ |

**Command Injection** — `;whoami` lalu `|id`:

![CMDi `;whoami` → 403 → Wazuh 100702](../../../Labs/waf/modsecurity-scratch/asset/cmdi-whoami.gif)
![CMDi `|id` → 403 → Wazuh 100702](../../../Labs/waf/modsecurity-scratch/asset/cmdi-pipe-id.gif)

**SQL Injection** — `1' ORDER BY 1-- -` lalu `1' OR 1=1`:

![SQLi `ORDER BY` → 403 → Wazuh 100703](../../../Labs/waf/modsecurity-scratch/asset/sqli-orderby.gif)
![SQLi `OR 1=1` → 403 → Wazuh 100703](../../../Labs/waf/modsecurity-scratch/asset/sqli-or1eq1.gif)

**XSS** — `<script>alert(1)</script>`:

![XSS `<script>` → 403 → Wazuh 100704](../../../Labs/waf/modsecurity-scratch/asset/xss-script.gif)

### 3. Bukti alert Wazuh

Field kunci dari alert `100702` (Command Injection):

| Field | Nilai |
|-------|-------|
| `rule.id` | `100702` |
| `rule.level` | `10` |
| `rule.description` | `WAF: Command Injection diblokir dari 192.168.43.63` |
| `rule.mitre.id` | `T1190` |
| `rule.mitre.tactic` | `Initial Access` |
| `rule.mitre.technique` | `Exploit Public-Facing Application` |
| `data.transaction.client_ip` | `192.168.43.63` (IP Kali — **bukan** IP WAF) |
| `data.transaction.request.uri` | `/vulnerabilities/exec/` |
| `agent.name` | `waf` (id `006`) |

Source IP = **attacker**, bukan WAF — artinya analis bisa langsung tau siapa yang nyerang, bukan cuma "ada yang diblok".

---

## Catatan

- **Desain match-blob kebukti tahan banting.** Di alert XSS, `messages[]` isinya 3 elemen (PL1 + PL2 + anomaly score `100999`) dan `tags`-nya sampe **nested array** — tapi `100704` tetap fire karena substring `attack-xss` ada di blob. Kalau maksain `transaction.messages.details.tags`, pasti gagal.
- **Reusable ke CRS.** Tag `attack-sqli` & `attack-xss` sama persis di OWASP CRS → `100703`/`100704` langsung jalan tanpa ubahan. Command Injection beda: CRS pakai tag `attack-rce`, bukan `attack-command-injection` — kalau nanti pasang CRS, `100702` tinggal ditambah alternation `attack-command-injection|attack-rce`.
- **`SecAuditLogRelevantStatus` ngatur apa yang ke-log.** Normal request (200) gak masuk audit log sama sekali → gak ada noise di SIEM. Bedain sama access log (semua request) yang sengaja **gak** di-forward di tahap ini.
