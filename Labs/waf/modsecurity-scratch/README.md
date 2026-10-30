# WAF Lab — ModSecurity Build from Scratch

> ✅ **STATUS: LIVE.** Deteksi end-to-end tervalidasi 2026-10-30 — serangan dari Kali diblok WAF (403) dan muncul jadi alert di Wazuh (rule `100702`/`100703`/`100704`, MITRE `T1190`).

## Tujuan

Adu serangan web dari **Kali** ke DVWA lewat **WAF ModSecurity rakitan sendiri**, terus nilai dua hal:

1. **Response** — payload **diblok** (403 + halaman error custom) vs **lolos** ke backend.
2. **Detection** — block-nya kecatat di audit log ModSec → di-forward ke **Wazuh** → jadi **alert SIEM** dengan source IP attacker + mapping MITRE.

Filosofi lab: **deteksi dulu**. WAF-nya udah nge-block (itu prevention, dibangun di Infrastructure); di sini fokus mastiin block-nya **kelihatan di SOC**.

- **Infrastruktur / cara bikin**: [`Infrastructure/waf/modsecurity-scratch/`](../../../Infrastructure/waf/modsecurity-scratch/README.md) — build engine (Tahap 1–3), SecRule sendiri (Tahap 4), integrasi Wazuh (Tahap 5).
- **Rule Wazuh**: [`Detection-Engineer/wazuh/rule/waf_rules.xml`](../../../Detection-Engineer/wazuh/rule/waf_rules.xml) (`100700`–`100704`).

---

## Topologi serangan

```
Kali (192.168.43.63) ──serangan web──> WAF (192.168.43.100) ──block 403──> modsec_audit.log
       attacker eksternal                   ModSecurity                          │
                                                                  Wazuh Agent ────┤
                                                                                  ▼
                                                            Wazuh Manager (Dell) ── ALERT (T1190)
```

## Prerequisites

- WAF ModSecurity live (Tahap 1–4) + integrasi Wazuh (Tahap 5) udah jalan.
- DVWA `security=low`, punya session (`PHPSESSID`).
- Kali (`192.168.43.63`) bisa reach WAF (`192.168.43.100`).

---

## Skenario & Bukti

Tiap serangan dijalanin dari Kali ke DVWA via WAF. Ekspektasi: **403** di sisi attacker, **alert** di sisi SOC.

### 1. Command Injection — DVWA `exec` (POST `ip`)

Nyoba inject command lewat field `ip` (`;whoami` lalu variasi `|id`):

```bash
curl -b "$C" "$WAF/vulnerabilities/exec/" --data "ip=;whoami&Submit=Submit"   # -> 403
curl -b "$C" "$WAF/vulnerabilities/exec/" --data "ip=|id&Submit=Submit"       # -> 403
```

![CMDi `;whoami` → 403 → Wazuh 100702](asset/cmdi-whoami.gif)
![CMDi `|id` → 403 → Wazuh 100702](asset/cmdi-pipe-id.gif)

- **WAF**: `403` — ModSec rule `100005` (`deny` langsung, match `ARGS:ip`).
- **Wazuh**: **`100702`** (level 10) — *WAF: Command Injection diblokir dari 192.168.43.63*.

### 2. SQL Injection — DVWA `sqli` (GET `id`)

Nyoba probe kolom (`ORDER BY`) lalu bypass auth (`OR 1=1`):

```bash
curl -b "$C" -G "$WAF/vulnerabilities/sqli/" --data-urlencode "id=1' ORDER BY 1-- -" --data "Submit=Submit"  # -> 403
curl -b "$C" -G "$WAF/vulnerabilities/sqli/" --data-urlencode "id=1' OR 1=1" --data "Submit=Submit"          # -> 403
```

![SQLi `ORDER BY` → 403 → Wazuh 100703](asset/sqli-orderby.gif)
![SQLi `OR 1=1` → 403 → Wazuh 100703](asset/sqli-or1eq1.gif)

- **WAF**: `403` — `100001` (libinjection `@detectSQLi`) nyumbang skor → `100999` `deny` (anomaly score ≥ 5).
- **Wazuh**: **`100703`** (level 10) — *WAF: SQL Injection diblokir*.

### 3. XSS — DVWA `xss_r` (GET `name`)

Inject script tag reflektif:

```bash
curl -b "$C" -G "$WAF/vulnerabilities/xss_r/" --data-urlencode "name=<script>alert(1)</script>"   # -> 403
```

![XSS `<script>` → 403 → Wazuh 100704](asset/xss-script.gif)

- **WAF**: `403` — `100002` (libinjection `@detectXSS`) + `100003` (taglist PL2) → `100999` `deny`. Audit log 3 message, tag `attack-xss` sampe nested array.
- **Wazuh**: **`100704`** (level 10) — *WAF: XSS diblokir*.

### 4. Normal request (negatif)

```bash
curl -b "$C" "$WAF/login.php"   # -> 200
```

- **WAF**: `200` — gak match rule apapun, lolos ke DVWA.
- **Wazuh**: **gak ada alert** — `SecAuditEngine RelevantOnly` gak nyatet response 200, jadi gak ada noise di SIEM. Ini bukti **WAF + deteksi gak false positive** ke trafik sah.

---

## Hasil deteksi

| Kategori | Payload | WAF | ModSec rule | **Wazuh rule.id** | Level | MITRE |
|----------|---------|-----|-------------|-------------------|-------|-------|
| Command Injection | `;whoami` / `\|id` | 403 | `100005` deny | **`100702`** | 10 | T1190 |
| SQL Injection | `1' ORDER BY 1-- -` / `1' OR 1=1` | 403 | `100001` → `100999` | **`100703`** | 10 | T1190 |
| XSS | `<script>alert(1)</script>` | 403 | `100002`+`100003` → `100999` | **`100704`** | 10 | T1190 |
| Normal | `GET /login.php` | 200 | — | **tidak ada** | — | — |

**Yang didapat analis SOC dari tiap alert**: `data.transaction.client_ip` = **`192.168.43.63`** (IP Kali, bukan IP WAF), `request.uri` (endpoint yang diserang), kategori serangan, dan tactic *Initial Access* / technique *Exploit Public-Facing Application*. Jadi bukan cuma "ada yang diblok", tapi **siapa nyerang apa**.

### Wujud alert di Wazuh

Contoh alert Command Injection (`100702`) — di-trim ke field inti (header request dibuang):

```json
{
  "rule": {
    "id": "100702",
    "level": 10,
    "description": "WAF: Command Injection diblokir dari 192.168.43.63",
    "mitre": {
      "id": ["T1190"],
      "tactic": ["Initial Access"],
      "technique": ["Exploit Public-Facing Application"]
    },
    "groups": ["modsecurity", "waf"]
  },
  "agent": { "name": "waf", "id": "006", "ip": "10.10.10.5" },
  "data": {
    "transaction": {
      "client_ip": "192.168.43.63",
      "is_interrupted": "true",
      "request": { "method": "POST", "uri": "/vulnerabilities/exec/" },
      "response": { "http_code": "403" },
      "messages": [
        {
          "message": "Command Injection Attack Detected",
          "details": {
            "ruleId": "100005",
            "file": "/etc/nginx/modsec/rules/rules-command-injection.conf",
            "match": "... against variable `ARGS:ip' (Value: `;whoami' )",
            "tags": ["paranoia-level/1", "attack-command-injection"]
          }
        }
      ]
    }
  }
}
```

Alir dari log mentah ke alert: `data.transaction.*` = isi audit log ModSec hasil decode JSON; `rule.*` = hasil match [`waf_rules.xml`](../../../Detection-Engineer/wazuh/rule/waf_rules.xml) (`100005` ModSec → tag `attack-command-injection` → Wazuh `100702`); `rule.mitre.*` = auto-enrich dari DB MITRE Wazuh via `T1190`.

## Catatan

- **Detection ≠ blocking dua-duanya kebukti**: serangan diblok di WAF *dan* kecatat di SIEM, sementara trafik normal lolos *tanpa* nyampah alert.
- **Robustness rule**: kategori di-deteksi lewat substring tag di blob `transaction.messages` (bukan field bersarang yang gak eksis di JSON decoder Wazuh) — detail di [Tahap 5](../../../Infrastructure/waf/modsecurity-scratch/05-wazuh-integration.md#4-decoder--gak-perlu-custom).
