# n8n — Setup Workflow Korelasi Fase 2 (Full Chain Detection)

## Tujuan

Bikin workflow n8n baru (terpisah dari workflow Fase 1) yang jalan **pull/scheduled**, bukan push seperti webhook Fase 1: tiap N menit manggil `POST /correlate/tick` — route Fase 2 di `AI-Rag-Integration/api-service.py` (service yang sama juga serve `/triage` Fase 1, logic korelasinya sendiri ada di `correlation_logic.py`), lalu buat tiap incident yang di-finalize — bikin ticket Jira **"Incident"** baru, **issue link** ke semua ticket Fase 1 anggotanya, dan notifikasi Discord.

Kenapa workflow terpisah dari Fase 1 (bukan nambahin node ke workflow "SOC Lab" yang udah ada) dan kenapa arsitektur pull bukan push, sudah dijelasin di memory desain Fase 2 — gak diulang di sini. Prasyarat: [`alert_id` sudah di-embed ke Description ticket Jira Fase 1](./n8n-alerting-pipeline-setup.md#7-update--embed-alert_id-di-description-jira-prasyarat-fase-2) (lihat step 7 di doc setup Fase 1), karena workflow ini nyari ticket lama lewat JQL berdasar teks itu.

---

## Prerequisites

- Workflow Fase 1 ("SOC Lab") sudah aktif & confirmed jalan — lihat [`n8n-alerting-pipeline-setup.md`](./n8n-alerting-pipeline-setup.md)
- Step 7 di atas (embed `alert_id`) sudah diterapkan ke node "Ticketing Jira"
- `api-service.py` bisa dijalanin di M1 (`uvicorn api-service:app --host 0.0.0.0 --port 8000`, dari folder `AI-Rag-Integration/` — proses yang sama dengan Fase 1, bukan proses terpisah), env var `WAZUH_INDEXER_HOST/PORT/USER/PASSWORD` sudah diisi
- Credential Jira yang sama dengan Fase 1 (`Jira SW Cloud account`) — dipakai ulang, bukan bikin baru

---

## Step-by-Step

Buat **workflow baru** di n8n (jangan nambahin ke workflow "SOC Lab" existing), namain misal `SOC Lab — Correlation`.

### 1. Node — Schedule Trigger

Trigger Interval: **Minutes**, tiap **15 menit** (disaranin `correlation_logic.py`, samain sama `SILENCE_THRESHOLD_MINUTES / 2`).

### 2. Node — HTTP Request `Correlate Tick`

- Method: `POST`
- URL: `http://<IP-M1>:8000/correlate/tick` (host & port **sama persis** dengan node "AI + RAG Triage" Fase 1 — 1 service, 2 route)
- Body: kosong (endpoint gak butuh input)

Response: `{"new_alerts_processed": <int>, "finalized_incidents": [{"incident_id", "host_name", "narrative", "alert_ids": [...]}]}` — atau `{"error": "..."}` (HTTP 500) kalau service exception.

### 3. Node — IF `Ada Incident?`

Kondisi (tipe Number): `{{ $json.finalized_incidents.length }}` **larger than** `0`.

Cabang **false** gak perlu disambung kemana-mana (tick kosong, selesai).

### 4. Node — Split Out `Per Incident` (cabang true)

Field to Split Out: `finalized_incidents`. Tiap item output sekarang = 1 incident (`incident_id`, `host_name`, `narrative`, `alert_ids`).

### 5. Node — Code `Build JQL Query`

Gabungin semua `alert_ids` dalam 1 incident jadi satu query JQL (OR per alert, phrase match biar gak salah tokenize angka desimal `timestamp.counter` ala Wazuh):

```js
const incident = $json;
const clauses = incident.alert_ids.map(id => `description ~ "\\"${id}\\""`);
const jql = `project = KAN AND (${clauses.join(' OR ')})`;

return { ...incident, jql };
```

⚠️ **Belum divalidasi** — asumsi operator `~` (text search) Jira bisa exact-match ID kayak `1691425200.123456` kalau dibungkus phrase (`\"...\"`). Jira tokenizer bisa mecah angka di titik desimal; phrase search harusnya tetep match karena posisi token berurutan, tapi ini **perlu ditest ke instance Jira asli** sebelum dipercaya — kalau ternyata meleset, pertimbangkan JQL search satu-satu per `alert_id` (lebih lambat tapi lebih presisi) ketimbang di-OR sekaligus.

### 6. Node — HTTP Request `JQL Search Query`

- Method: `GET`
- URL: `https://<jira-domain>.atlassian.net/rest/api/3/search`
- Query Parameters: `jql` = `{{ $json.jql }}`, `fields` = `key`
- Authentication: **Predefined Credential Type** → pilih **Jira Software Cloud API** → credential `Jira SW Cloud account` (reuse dari Fase 1, bukan bikin baru)

> Cek dulu apakah node native **Jira** di versi n8n yang kepasang punya operation "Issue Search" (resource Issue) yang terima JQL langsung — kalau ada, lebih simpel pakai itu daripada HTTP Request manual ke REST API. Kalau gak ada/versinya beda, HTTP Request di atas jadi fallback yang pasti works karena manggil REST API Jira langsung.

Response: `{"issues": [{"key": "KAN-219", ...}, ...]}`.

### 7. Node — Jira `Create Incident Ticket`

Node native **Jira**, operation **Create**. HTTP Request node sebelumnya (step 6) cuma balikin response search API-nya, field incident (`incident_id`, `host_name`, `narrative`) udah gak ada di `$json` — makanya field-field di bawah **rujuk balik langsung ke node "Build JQL Query"** (`$('Build JQL Query')`) lewat expression, bukan dari `$json` node ini. Gak perlu node Code perantara buat "nyelametin" field yang hilang — n8n expression bisa reference node manapun, gak cuma node sebelumnya langsung.

- Project: `KAN` (samain Fase 1)
- Issue Type: `Task` (atau bikin issue type custom `Incident` di Jira kalau mau lebih rapi — belum dibikin, masih pakai `Task` generik dulu)
- Summary: `=Korelasi Insiden — {{ $('Build JQL Query').item.json.host_name }} ({{ $('Build JQL Query').item.json.incident_id }})`
- Description: `={{ $('Build JQL Query').item.json.narrative }}`

Credential: `Jira SW Cloud account` (sama kayak Fase 1).

### 8. Node — Code `Merge For Link`

Jira Create node cuma balikin field ticket baru (termasuk `key`), gak bawa `jira_keys`. Sama kayak step 7, gak perlu node Code perantara buat itu — extract langsung dari node "JQL Search Query" (step 6):

```js
const keys = ($('JQL Search Query').item.json.issues || []).map(i => i.key);

return {
  new_ticket_key: $json.key,
  jira_keys: [...new Set(keys)]
};
```

### 9. Node — Split Out `Per Jira Key`

Field to Split Out: `jira_keys`. Opsi **Include** → pastiin field lain (`new_ticket_key`) ikut kebawa di tiap item hasil split.

### 10. Node — HTTP Request `Create Issue Link`

- Method: `POST`
- URL: `https://<jira-domain>.atlassian.net/rest/api/3/issueLink`
- Authentication: Predefined Credential Type → `Jira SW Cloud account` (sama kayak step 6)
- Body (JSON):

```json
{
  "type": { "name": "Relates" },
  "inwardIssue": { "key": "{{ $json.jira_keys }}" },
  "outwardIssue": { "key": "{{ $json.new_ticket_key }}" }
}
```

⚠️ Nama link type `"Relates"` diasumsikan ada persis kayak itu di default scheme Jira Cloud (biasa muncul di UI sebagai "relates to") — belum dicek ke `GET /rest/api/3/issueLinkType` instance ini. Kalau API balikin 400 soal `type.name` invalid, cek endpoint itu buat nama yang valid.

### 11. Node — HTTP Request `Push Notif Discord` (paralel dari step 8 "Merge For Link", bukan lanjutan step 10)

Sama pola kayak Fase 1 (`n8n-nodes-base.httpRequest`, POST ke Discord webhook, body JSON `content`). Input langsung node ini = output "Merge For Link" (`{ new_ticket_key, jira_keys }`) — `host_name` gak ikut kebawa di situ, jadi diambil balik dari node "Build JQL Query":

```
🔗 [Korelasi] Incident baru {{ $json.new_ticket_key }} — host {{ $('Build JQL Query').item.json.host_name }}
Link: https://<jira-domain>.atlassian.net/browse/{{ $json.new_ticket_key }}
```

`{{ $json.new_ticket_key }}` dipakai langsung (bukan `$('Create Incident Ticket')...`) karena node ini nyambung langsung dari "Merge For Link", bukan dari "Create Incident Ticket".

---

## Verifikasi

- [ ] Workflow baru `SOC Lab — Correlation` dibikin & di-**Activate**
- [ ] Test manual: trigger node 2 (`Correlate Tick`) secara manual (klik "Execute step") — cek response `finalized_incidents` sesuai ekspektasi
- [ ] JQL search (step 6) beneran ketemu ticket Fase 1 yang match — validasi asumsi phrase search di step 5
- [ ] Ticket Jira "Incident" baru ke-create (step 7) dengan Description = narrative dari AI
- [ ] Issue link (step 10) muncul di tab "Links" ticket Incident, ngarah ke semua ticket Fase 1 anggota
- [ ] Notifikasi Discord (step 11) masuk dengan link yang benar
- [ ] Jalanin skenario command injection ulang (atau replay full attack chain) buat validasi micro-cluster window (10 detik) & silence threshold (30 menit) end-to-end pakai data real

---

## Catatan

Doc ini murni **desain + instruksi step-by-step**, belum ada satupun node yang dites hidup ke instance n8n/Jira asli — beda dari `n8n-alerting-pipeline-setup.md` yang tiap stepnya udah ditandain ✅ confirmed. Konsisten sama pola project ini: asumsi ditulis eksplisit (⚠️), dikoreksi setelah dieksekusi nyata. Begitu ada bagian yang udah dites, update doc ini (atau catat di memory) sebelum lanjut bikin writeup lab Fase 2.
