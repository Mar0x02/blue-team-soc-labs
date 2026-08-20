# n8n — Setup Alerting & Ticketing Pipeline (Wazuh → n8n → Jira + Discord)

## Tujuan

Bangun layer orkestrasi antara Wazuh (Dell) dan dua service konsumen — **Jira** (ticketing, system of record buat analyst) dan **Discord** (notification, sinyal real-time) — supaya SOC analyst gak harus mantengin Wazuh Dashboard seharian buat nangkep alert penting (alert fatigue). n8n dipilih sebagai layer orkestrasi/glue, **bukan** pengganti ticketing system-nya sendiri — mirip pola yang dipakai perusahaan yang gak punya budget SOAR enterprise (Splunk SOAR/XSOAR), yang biasanya pakai tool low-code (Tines, Torq, atau n8n) buat nyambungin SIEM ke tool operasional lain.

Arsitektur:

```
Wazuh Manager (Dell)  --webhook-->  n8n (M1, native macOS)  --branch-->  Jira Cloud (ticket baru)
                                                              --branch-->  Discord (notifikasi)
```

Penting: seluruh pipeline ini **tanpa automated response/action** — n8n cuma merutekan alert ke tempat yang lebih gampang dilihat manusia, keputusan & tindakan tetap manual oleh analyst. Ini konsisten sama roadmap belajar project (`detection → cleaning → prevention → SOAR`) — pipeline ini bukan masuk tahap SOAR karena gak ada aksi otomatis, cuma mempermudah proses triage di tahap detection.

n8n dipasang di **M1** (bukan PC) — kolokasi sama Ollama. Alasan utamanya buat langkah AI/RAG enrichment berikutnya (tahap setelah pipeline ini jalan): begitu n8n perlu manggil API Ollama buat nambahin konteks ke alert, panggilannya jadi `localhost` (n8n dan Ollama sama-sama di M1), bukan nyebrang network ke device lain. Nambah node HTTP Request ke API Ollama/RAG nanti tinggal nyisipin di antara webhook dan branch Jira/Discord — gak perlu ubah arsitektur network.

Jira sendiri tetap **Jira Cloud** (SaaS, id.atlassian.com) — bukan service yang di-host di device manapun di lab ini, jadi gak ada "penempatan" khusus. Setup project/API token-nya bisa dilakuin dari browser device manapun (PC, M1, laptop lain), gak ngaruh ke arsitektur pipeline.

---

## Prerequisites

- Wazuh Manager di Dell sudah running dan bisa generate alert — lihat [`wazuh-setup.md`](./wazuh-setup.md)
- M1 reachable dari Dell lewat network hotspot (`192.168.43.x`) — sama kayak setup `OLLAMA_HOST=0.0.0.0` yang udah ada buat cross-device Ollama access, M1 posisinya di luar pfSense, jadi gak ada hop firewall tambahan buat webhook call ke n8n
- Akun Jira Cloud (gratis, [id.atlassian.com](https://id.atlassian.com)) — dipakai buat bikin project ticketing
- Server/channel Discord sendiri (buat bikin Incoming Webhook)
- Docker Desktop di M1 (macOS, Apple Silicon) — install kalau belum ada

---

## Step-by-Step

### 1. Install & Jalankan n8n (Docker, di M1)

n8n dijalanin native di M1 (bukan PC) — kolokasi sama Ollama, alasannya dijelasin di section Tujuan (AI enrichment call jadi `localhost` nanti).

```bash
docker volume create n8n_data
docker run -d --name n8n --restart unless-stopped -p 5678:5678 -v n8n_data:/home/node/.n8n -e N8N_SECURE_COOKIE=false n8nio/n8n
```

✅ **Confirmed** — command di atas jalan mulus di M1 tanpa gotcha: `N8N_SECURE_COOKIE=false` gak nimbulin masalah akses via `http://`, dan image `n8nio/n8n` jalan native ARM64 tanpa warning platform mismatch.

Cek container jalan:

```bash
docker ps
```

> **Update 2026-08-06 — butuh Python di Code node (enrichment alert):** image `n8nio/n8n` official base-nya sekarang "Docker Hardened Image" (Alpine yang di-strip termasuk `apk`-nya sendiri) — Code node mode Python bakal error `python3 is missing from this system`, dan `apk add python3` langsung juga gagal (`apk: not found`). Fix-nya multi-stage build di [`n8n/Dockerfile`](./n8n/Dockerfile): install `python3` di stage Alpine biasa (masih ada `apk`), baru di-copy ke image `n8nio/n8n` yang hardened. ✅ **Confirmed** — di-build & dites langsung: `python3` jalan normal (`import json` dll berhasil), dan n8n tetap boot sempurna (healthcheck `200`, semua migration jalan) — gak ada yang kebreak akibat copy `/usr` + `/lib`.
>
> ```bash
> cd Infrastructure/n8n
> docker build -t n8n-with-python .
> ```
>
> Terus ganti command run di atas, image terakhirnya jadi `n8n-with-python` (bukan `n8nio/n8n`) — volume `n8n_data` yang sama tetep dipakai, jadi workflow/credential yang udah ada gak hilang:
>
> ```bash
> docker stop n8n && docker rm n8n
> docker run -d --name n8n --restart unless-stopped -p 5678:5678 -v n8n_data:/home/node/.n8n -e N8N_SECURE_COOKIE=false n8n-with-python
> ```

### 2. Buat Owner Account & Cek IP M1

Buka `http://localhost:5678` dari browser M1, ikutin wizard buat bikin owner account pertama.

Catat IP M1 di jaringan hotspot (dipakai nanti buat `hook_url` dari sisi Dell) — kemungkinan besar udah dicatat sebelumnya pas setup `OLLAMA_HOST` cross-device, tinggal reuse:

```bash
ifconfig | grep "inet " 
# catat IP dari interface yang connect ke hotspot 192.168.43.x
```

### 3. Bikin Jira Project + API Token

1. Login ke [id.atlassian.com](https://id.atlassian.com), buat site Jira Cloud kalau belum ada.
2. Di sidebar **Spaces** → **Create** → pilih tipe **Team-managed**, kasih nama. Catatan terminologi: UI Jira terbaru nyebut ini **"Space"**, bukan "Project" lagi kayak dokumentasi lama — tapi **project key** (dipakai di API/node n8n) tetap konsep yang sama, cuma auto-generate dari nama space (gak bisa dipilih manual kalau nama space-nya gak diedit).
3. Generate API token: **Profile → Manage account → Security → Create and manage API tokens → Create API token** — copy tokennya (cuma muncul sekali).

✅ **Confirmed** — space **"CyberSecurity Lab"** udah dibikin, project key auto-generate jadi **`KAN`** (bukan `SOCLAB` kayak contoh di atas — pakai `KAN` buat konfigurasi node Jira di n8n nanti). Tiga task contoh (`KAN-1`/`KAN-2`/`KAN-3`) yang muncul otomatis itu cuma seed data onboarding Jira, aman dihapus/diabaikan. API token udah di-generate — lihat `jira-passwords.txt` (gitignored).

### 4. Bikin Discord Incoming Webhook

1. Di channel Discord tujuan → **Edit Channel → Integrations → Webhooks → New Webhook**.
2. Kasih nama (misal `wazuh-alert-bot`), copy **Webhook URL**-nya.

✅ **Confirmed** — webhook `wazuh-alert-bot` udah dibikin — lihat `discord-passwords.txt` (gitignored).

Pendekatan ini sengaja pakai Incoming Webhook (`HTTP Request` node biasa di n8n, POST JSON `{"content": "..."}`) — bukan native Discord node (Bot API) — karena gak butuh setup Developer Portal/bot, dan gak tergantung versi node n8n yang bisa beda-beda opsi auth-nya antar rilis. Kalau nanti butuh fitur lebih kaya (embed, mention role), baru pertimbangin upgrade ke Bot API.

### 5. Bikin Workflow di n8n

Di n8n UI, buat workflow baru:

1. **Node 1 — Webhook** (trigger): method `POST`, path bebas misal `wazuh-alert`. Simpan dulu **Test URL**-nya buat verifikasi di Step 7, nanti dapet **Production URL** setelah workflow di-**Activate**.
2. **Node 2 — Jira Software** (branch 1): butuh credential baru (email Atlassian + API token dari `jira-passwords.txt` + domain site, misal `yourname.atlassian.net`). Operation: **Create**, Project: `KAN`, Issue Type: `Task` (atau bikin custom issue type "Security Alert" di Jira kalau mau lebih rapi), Summary: mapping dari field `rule.description` payload webhook, Description: raw JSON alert atau ringkasan (`agent.name`, `rule.level`, `rule.id`, `timestamp`).
3. **Node 3 — HTTP Request** (branch 2, paralel dari Webhook): method `POST`, URL: Discord webhook dari Step 4, Body: JSON `{"content": "🚨 [Wazuh] {{ $json.rule.description }} — level {{ $json.rule.level }} — agent {{ $json.agent.name }}"}` (sesuaikan field mapping ke payload asli yang dikirim Wazuh).
4. **Activate** workflow, copy **Production Webhook URL** (contoh: `http://<IP-M1>:5678/webhook/wazuh-alert`).

✅ **Confirmed** — workflow udah di-Activate, test kirim payload manual via curl ke webhook berhasil: ticket baru muncul di Jira dan pesan masuk ke Discord. Node Jira + Discord (credential & mapping field) confirmed jalan.

### 6. Setup Wazuh Integrator (Dell) — kirim alert ke n8n

Wazuh punya mekanisme **Integrator** buat forward alert ke external webhook (pola yang sama kayak integrasi Slack/PagerDuty bawaan Wazuh), lewat custom integration script.

Bikin wrapper script `/var/ossec/integrations/custom-n8n` (executable, tanpa ekstensi):

```bash
#!/bin/sh
WPYTHON_BIN="framework/python/bin/python3"
SCRIPT_PATH_NAME="$0"
DIR_NAME="$(cd $(dirname ${SCRIPT_PATH_NAME}); pwd)"
SCRIPT_NAME="$(basename ${SCRIPT_PATH_NAME})"
case ${DIR_NAME} in
    */bin | */integrations)
        if [ -z "${WAZUH_PATH}" ]; then
            WAZUH_PATH="$(cd ${DIR_NAME}/..; pwd)"
        fi
    ;;
    *)
        echo "Unable to determine Wazuh's installation."
        exit 1
    ;;
esac
${WAZUH_PATH}/${WPYTHON_BIN} ${DIR_NAME}/${SCRIPT_NAME}.py $@
```

Dan `/var/ossec/integrations/custom-n8n.py`:

```python
#!/usr/bin/env python3
import sys
import json
import requests

alert_file = sys.argv[1]
webhook_url = sys.argv[3]

with open(alert_file) as f:
    alert_json = json.load(f)

requests.post(webhook_url, json=alert_json, timeout=10)
```

Set permission (harus `750`, owner `root:wazuh`, sama kayak integration script bawaan):

```bash
sudo chmod 750 /var/ossec/integrations/custom-n8n /var/ossec/integrations/custom-n8n.py
sudo chown root:wazuh /var/ossec/integrations/custom-n8n /var/ossec/integrations/custom-n8n.py
```

Tambahin block `<integration>` di `ossec.conf` (Wazuh Manager):

```xml
<integration>
  <name>custom-n8n</name>
  <hook_url>http://<IP-M1>:5678/webhook/wazuh-alert</hook_url>
  <level>7</level>
  <alert_format>json</alert_format>
</integration>
```

> **Catatan threshold:** `<level>7</level>` dipasang sementara sebagai baseline umum (default level actionable Wazuh) — begitu custom rule di `Detection-Engineer/wazuh/` (yang belum di-deploy ke Dell) resmi diaktifin, nilai ini perlu di-tuning ulang biar selaras sama severity yang udah didesain di sana (misal cuma forward level ≥10, biar Jira/Discord gak kebanjiran alert level rendah).

Restart manager:

```bash
sudo systemctl restart wazuh-manager
```

> **Catatan (belum divalidasi live):** struktur script custom integration di atas based on pola dokumentasi resmi Wazuh — path `framework/python/bin/python3` dan struktur `case` bisa beda tergantung versi Wazuh yang ke-install di Dell. Wajib dicek dulu apakah path itu valid sebelum dianggap final (`ls /var/ossec/framework/python/bin/`), dan cek `ossec.log` kalau integrator gagal jalan.

### 7. Update — Embed `alert_id` di Description Jira (prasyarat Fase 2)

Route korelasi Fase 2 (`POST /correlate/tick`, logic di `AI-Rag-Integration/correlation_logic.py`, di-serve bareng `/triage` dari `api-service.py`) perlu nyari ticket Jira Fase 1 per alert lewat JQL search pas nge-finalize sebuah incident (detail di [`n8n-correlation-workflow-setup.md`](./n8n-correlation-workflow-setup.md)). Buat itu bisa jalan, node **"Ticketing Jira"** (existing, dari Step 5) perlu nambahin ID unik tiap alert ke field **Description**.

Wazuh nyimpen ID unik ini di field top-level `id` alert (**bukan** `rule.id` — itu ID rule/signature, bukan ID kejadian spesifik). Field ini ikut kebawa flat lewat `...alert` di node "Logic Enrichment Summary", jadi bisa diakses `{{ $json.id }}` di node-node setelahnya tanpa perubahan lain.

Ubah expression **Description** di node "Ticketing Jira" jadi:

```
=Agent: "{{ $json.agent.name }}"
Level: {{ $json.rule.level }}
Rule ID: {{ $json.rule.id }}
Alert ID: {{ $json.id }}
{{ $json.enriched_summary }}
{{ $json.triage }}
```

⚠️ **Belum divalidasi** — asumsi field top-level `id` beneran ada di payload yang dikirim Wazuh Integrator (harusnya iya, karena `custom-n8n.py` cuma `json.load()` file alert mentah tanpa strip field apapun sebelum di-POST), tapi belum dicek langsung ke eksekusi n8n asli. Cek tab **Executions** (klik salah satu run, lihat output node "Logic Enrichment Summary") buat mastiin `id` beneran muncul sebelum lanjut ke Fase 2.

---

## Verifikasi

- [x] `docker ps` di M1 nunjukin container `n8n` status **Up**
- [x] Workflow n8n ter-**Activate**, Production Webhook URL udah dicatat
- [x] Test kirim payload manual ke webhook n8n (`curl -X POST http://localhost:5678/webhook/wazuh-alert -H "Content-Type: application/json" -d '{"rule":{"description":"test","level":10,"id":"999999"},"agent":{"name":"test-agent"}}'`) — cek muncul **ticket baru di Jira** dan **pesan baru di Discord**
- [ ] Setup Wazuh Integrator (Dell) — step 6 belum dieksekusi
- [ ] Generate alert asli dari Dell (`sudo tail -f /var/ossec/logs/ossec.log` sambil trigger event yang match rule level ≥7) — cek alert beneran nyampe ke n8n → Jira → Discord, bukan cuma test payload manual

---

## Catatan

Step 1–5 (n8n di M1, Jira, Discord, workflow) udah dieksekusi dan confirmed jalan lewat test payload manual. Step 6 (Wazuh Integrator di Dell) **belum** dieksekusi — beberapa detail di situ (path Python `framework/python/bin/python3`, struktur script, level threshold `7`) masih asumsi berdasar pola umum dan perlu dikoreksi begitu dites langsung di Dell, konsisten sama pola dokumentasi lab lain di project ini (assumption ditulis eksplisit, dikoreksi setelah eksekusi nyata — bukan diklaim final dari awal).
