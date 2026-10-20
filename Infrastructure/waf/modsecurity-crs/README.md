# 🛡️ WAF Stack — ModSecurity + OWASP CRS (Image Resmi)

## Tujuan

Jalanin **ModSecurity v3 + OWASP CRS** sebagai reverse proxy di depan DVWA pakai image resmi `owasp/modsecurity-crs:nginx`. Image ini udah ngebundel tiga komponen sekaligus:

```
nginx (reverse proxy) ──connector──► libmodsecurity v3 (engine) ──load──► OWASP CRS (rules)
```

Tinggal arahin backend dan atur log lewat environment variable. Stack ini jadi baseline WAF yang **siap pakai**, sebelum komponen yang sama dirakit manual di [`../modsecurity-scratch/`](../modsecurity-scratch/README.md).

---

## Prerequisites

- WAF VM + Docker + agent Wazuh `waf` udah siap, lihat [`../README.md`](../README.md)
- DVWA di `10.10.10.10:80` jalan
- `:80` di WAF VM gak dipakai stack lain (SafeLine `down`)

---

## Step-by-Step

### 1. Config backend

`/data/waf/modsec-crs/.env`:

```ini
BACKEND_URL=http://10.10.10.10:80
```

IP backend ditaruh di `.env`, jangan di compose.

### 2. `docker-compose.yml`

`/data/waf/modsec-crs/docker-compose.yml`:

```yaml
services:
  modsec-crs:
    image: owasp/modsecurity-crs:nginx
    container_name: modsec-crs
    restart: unless-stopped
    env_file: .env
    environment:
      - BACKEND=${BACKEND_URL}
      - MODSEC_RULE_ENGINE=On
      - MODSEC_AUDIT_ENGINE=RelevantOnly
      - MODSEC_AUDIT_LOG=/var/log/modsec/audit.log
      - MODSEC_AUDIT_LOG_FORMAT=JSON
      - PARANOIA=1
      - ANOMALY_INBOUND=5
      - ANOMALY_OUTBOUND=4
    ports:
      - "80:8080"
    volumes:
      - ./logs:/var/log/modsec
```

| Env | Directive / fungsi |
|-----|--------------------|
| `BACKEND` | Target `proxy_pass` nginx |
| `MODSEC_RULE_ENGINE=On` | `SecRuleEngine`: `On` = block, `DetectionOnly` = cuma log |
| `MODSEC_AUDIT_ENGINE=RelevantOnly` | `SecAuditEngine`: log cuma transaksi yang match rule / anomali |
| `MODSEC_AUDIT_LOG_FORMAT=JSON` | Audit log JSON, gampang di-parse Wazuh |
| `PARANOIA=1` | Paranoia level CRS (1–4). Naik = deteksi lebih agresif + false positive naik |
| `ANOMALY_INBOUND=5` | Threshold anomaly score request. `5` = satu rule CRITICAL cukup buat block |
| `ANOMALY_OUTBOUND=4` | Threshold anomaly score response |
| `ports: 80:8080` | Nginx di container jalan non-root di `:8080`, di-map ke host `:80` (bridge mode) |

Image ini nge-render env var jadi file config waktu container start, jadi tuning dasar cukup lewat compose.

### 3. Permission folder log

Nginx worker di container nulis log sebagai **uid 101**. Folder log di host harus bisa ditulis uid itu, tanpa dibuka ke semua user:

```bash
mkdir -p /data/waf/modsec-crs/logs
sudo chown 101:101 /data/waf/modsec-crs/logs
sudo chmod 750 /data/waf/modsec-crs/logs
```

Jangan pakai `chmod 777`. Folder audit log harus dijaga integritasnya, karena isinya bukti serangan.

### 4. Jalanin

```bash
cd /data/waf/modsec-crs
docker compose up -d
docker compose logs -f
```

### 5. Ingest audit log ke Wazuh

Tambah ke `/var/ossec/etc/ossec.conf` di WAF VM:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/data/waf/modsec-crs/logs/audit.log</location>
</localfile>
```

```bash
sudo systemctl restart wazuh-agent
```

Audit log JSON → Wazuh auto-extract field-nya (`client_ip`, `uri`, messages + rule id, dll).

---

## Verifikasi

**Reverse proxy jalan (dari luar):**
```bash
curl -I http://<IP-WAN-pfSense>/
```

**Block serangan:**
```bash
curl "http://<IP-WAN-pfSense>/?id=1' OR '1'='1"     # → 403 Forbidden
```
Form POST DVWA juga ke-block, karena engine ikut inspeksi body request (`SecRequestBodyAccess On`).

**Rule CRS yang kena:**
```bash
grep -o '"ruleId":"[0-9]*"' /data/waf/modsec-crs/logs/audit.log | sort | uniq -c | sort -rn
```

**Log masuk Wazuh:** Discover → `agent.name: waf`.

✅ Confirmed live 2026-10-14:
- Serangan external dari M1 (`192.168.43.193`) → pfSense → WAF → **403** buat GET (query URL) maupun POST (form DVWA)
- `client_ip` di audit log = **IP attacker asli** (`192.168.43.193`)
- Event ModSec nyampe **Wazuh archives**. Belum jadi **alert**, karena belum ada rule Wazuh yang match (dikerjain di tahap custom rule)

---

## Catatan & Gotcha

- **`client_ip` vs `host_ip`** di audit log: `client_ip` = IP attacker asli, `host_ip` = IP container (`172.18.0.x`), cuma kosmetik. Bridge mode biasa udah cukup, gak perlu `network_mode: host` atau ubah `userland-proxy` Docker.
- **Header ke backend**: nginx di image ini ngirim `X-REAL-IP $remote_addr` (gak bisa dipalsuin client) dan `X-Forwarded-For $proxy_add_x_forwarded_for` (nambahin ke header kiriman client, bisa dipalsuin). Kalau backend butuh IP asli, pakai `X-Real-IP`.
- **Config di container itu ephemeral.** Custom rule / exclusion harus di-bind-mount dari host (misal `./custom-rules:/etc/modsecurity.d/custom-rules:ro`), jangan diedit di dalam container.
- **ID custom rule** pakai range `100000–199999`. Range `900000–999999` dipakai CRS.
