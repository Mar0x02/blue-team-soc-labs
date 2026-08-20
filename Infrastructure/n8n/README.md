# n8n — Alerting & AI Triage Pipeline

Folder ini berisi konfigurasi build **n8n** yang jadi layer orkestrasi antara Wazuh (Dell) dan service konsumen (Jira, Discord, dan segera Ollama buat AI triage). Detail step-by-step setup (termasuk log assumption → confirmed) ada di [`../n8n-alerting-pipeline-setup.md`](../n8n-alerting-pipeline-setup.md) — README ini fokus ke gambaran struktur & stack yang **jalan saat ini**.

---

## Struktur Folder

```
Infrastructure/n8n/
├── Dockerfile     # Custom image: n8nio/n8n:latest + python3
└── README.md      # File ini
```

---

## Stack yang Dipakai

| Komponen | Detail |
|----------|--------|
| **n8n** | Self-hosted, Docker, jalan di **M1** (kolokasi sama Ollama — biar panggilan AI nanti `localhost`). Image custom dari `Dockerfile` di folder ini. |
| **Base image** | `n8nio/n8n:latest` — sekarang berbasis **Docker Hardened Image (Alpine)**, gak bundle `apk`/`python3` sama sekali. `Dockerfile` di sini nambahin `python3` lewat multi-stage build (install di stage Alpine biasa, copy ke image hardened). |
| **Jira Cloud** | Ticketing — system of record buat analyst. |
| **Discord** | Notifikasi real-time — Incoming Webhook (bukan Bot API). |
| **Ollama + ChromaDB** | (Fase 1 AI+RAG, lihat [`AI-Rag-Integration/`](../../AI-Rag-Integration/)) — AI triage, jalan di M1 juga. |

> **Catatan soal `python3` di image:** workflow yang jalan sekarang pakai Code node **JavaScript**, bukan Python — Python Code node di n8n versi terbaru (`2.33.3`) butuh **Task Runner external mode** (sidecar container `n8nio/runners` terpisah), jauh lebih kompleks daripada yang dibutuhkan buat enrichment sederhana ini. `python3` tetap disiapin di image buat jaga-jaga kalau ke depan butuh Python beneran (misal library data science tertentu), tapi gak dipakai node manapun di workflow saat ini.

---

## Arsitektur Workflow n8n Saat Ini

```
Webhook (dari Wazuh Integrator, Dell)
   │
   ▼
Code in JavaScript  ── enrichment: bangun field `enriched_summary`
   │                    (nyesuain isi per source: Suricata network,
   │                    auditd process, FIM file, access.log HTTP —
   │                    fallback ke full_log kalau gak ada yang match)
   │
   ├──▶ Jira Software (Create Issue)   → ticket baru
   └──▶ HTTP Request (Discord Webhook) → notifikasi real-time
```

**Field mapping penting:** payload asli dari Wazuh Integrator nested di bawah `body` (`$json.body.rule`, `$json.body.data`, dst) sebelum masuk Code node. Code node **unwrap** isi `body` jadi flat di root output (`rule`, `data`, `agent`, `enriched_summary`) — jadi node-node setelahnya (Jira, Discord) baca langsung `{{ $json.rule.description }}`, **tanpa** prefix `body.` lagi.

---

## Referensi Terkait

- **Setup lengkap step-by-step**: [`Infrastructure/n8n-alerting-pipeline-setup.md`](../n8n-alerting-pipeline-setup.md)
- **Exception Suricata buat trafik Wazuh Agent → Manager** (biar gak numpuk false-positive di rule egress): [`Detection-Engineer/suricata-trigger-rule/custom.rules`](../../Detection-Engineer/suricata-trigger-rule/custom.rules) — SID `1000009`, pakai variable pfSense `$SIEM_HOST`
- **AI+RAG API** (Fase 1 `/triage` + Fase 2 `/correlate/tick`, 1 service): [`AI-Rag-Integration/api-service.py`](../../AI-Rag-Integration/api-service.py)
- **Setup workflow n8n Fase 2** (korelasi): [`Infrastructure/n8n-correlation-workflow-setup.md`](../n8n-correlation-workflow-setup.md)

---

## Roadmap AI+RAG (3 Fase)

1. **Fase 1 (done, baseline)** — Triage dasar + investigasi arah serangan, berdasarkan retrieval dari `soc_knowledge` (Sigma/YARA/MITRE/CVE/THM). Endpoint: `POST /triage` di `AI-Rag-Integration/api-service.py`, dipanggil dari node HTTP Request di workflow n8n ini (paralel dari Code node, sejajar Jira & Discord).
2. **Fase 2 (in progress)** — Korelasi log lintas-source/lintas-sensor jadi "full chain detection". Endpoint: `POST /correlate/tick` di service yang sama, dipanggil workflow n8n **terpisah** lewat Schedule Trigger — lihat [`n8n-correlation-workflow-setup.md`](../n8n-correlation-workflow-setup.md).
3. **Fase 3** — Integrasi third-party vendor (kalau memungkinkan).
