# Windows 7 — Setup FIM/Syscheck (Downloads + Temp)

## Tujuan

Aktifin **File Integrity Monitoring (FIM/syscheck)** Wazuh Agent di Win7 (`10.10.20.10`, LAN2), khusus monitor dua lokasi yang paling relevan buat rantai phishing/malware: folder **Downloads** (tempat file mendarat) dan folder **Temp** (tempat payload distaging dan dieksekusi) — buat lab [Phishing via Malicious LNK](<../Labs/os-client/Win-7/Initial Access/Phishing via Malicious LNK (T1566.001 + T1204.002)/README.md>).

Beda dari Sysmon (jejak **proses**), FIM ngasih sinyal independen dari layer **filesystem**: file apa yang mendarat dan payload apa yang di-drop. Di lab phishing LNK, dua sinyal ini yang nangkep sisi artefak serangan (`.lnk` mendarat + `update.exe` di-drop) — terlepas dari proses yang jalan belakangan, yang udah ditangani rule Sysmon.

Dua folder ini juga **ramai dipakai system dan user**, jadi kalau dipantau mentah bakal jadi sumber noise. Scope-nya sengaja dipersempit ke **ekstensi executable/script** aja, plus sebagian noise di-ignore.

---

## Prerequisites

- Win7 base OS + **Wazuh Agent 4.13 terinstall dan Active** (`WIN7-VICTIM` muncul Active di Dashboard) — lihat [`win7-wazuh-agent.md`](./win7-wazuh-agent.md)
- Akses **Administrator** di Win7 (buat edit `ossec.conf` + restart service)
- (Opsional, buat konteks lab) Sysmon udah jalan — lihat [`win7-sysmon.md`](./win7-sysmon.md). FIM jalan sendiri, gak butuh Sysmon, tapi di lab keduanya saling lengkap (file event + process event)

---

## Step-by-Step

### 1. Tambah direktori ke `<syscheck>` (Wazuh Agent, Win7)

Buka `ossec.conf` dengan **Notepad as Administrator**:

```
C:\Program Files\ossec-agent\ossec.conf
```

> Win7 ini 32-bit, jadi path agent-nya `Program Files` doang — **bukan** `Program Files (x86)`. Sama kayak note di [`win7-wazuh-agent.md`](./win7-wazuh-agent.md).

Cari block `<syscheck>` yang udah ada, tambahin dua scope di bawah.

**Downloads — semua user:**

```xml
<directories check_all="yes" realtime="yes" whodata="yes">C:\Users\*\Downloads</directories>
<ignore type="sregex">\.crdownload$|\.part$|\.tmp$|\.download$</ignore>
<restrict type="sregex">\.exe$|\.bat$|\.cmd$|\.ps1$|\.vbs$|\.msi$|\.scr$|\.dll$|\.lnk$</restrict>
```

**Temp — system + per-user:**

```xml
<directories check_all="yes" realtime="yes" whodata="yes">C:\Windows\Temp</directories>
<directories check_all="yes" realtime="yes" whodata="yes">C:\Users\*\AppData\Local\Temp</directories>
<restrict type="sregex">\.exe$|\.bat$|\.cmd$|\.ps1$|\.vbs$|\.js$|\.wsf$|\.msi$|\.scr$|\.dll$|\.com$|\.hta$|\.cpl$</restrict>
<ignore type="sregex">\.log$|\.tmp$|\.etl$|\.cab$</ignore>
```

| Opsi | Fungsi |
|------|--------|
| `realtime="yes"` | Deteksi langsung pas file muncul/berubah, gak nunggu scheduled scan (`frequency`) |
| `whodata="yes"` | Nempelin **proses & user** yang bikin perubahan. Di Windows, whodata pakai audit SACL (Wazuh yang atur SACL-nya otomatis pas `whodata=yes`) — bukan auditd kayak di Web-Server. Hasilnya alert bawa `audit.process` + `uname_after` |
| `restrict` | Cuma ekstensi executable/script yang dihitung. Di Downloads fokus ke `.lnk` (artefak phishing), di Temp ke stager exe (`.exe`, `.dll`, `.scr`, dst) |
| `ignore` | Buang noise turunan browser (`.crdownload`, `.part`) dan system (`.log`, `.etl`, `.cab`) |

`C:\Users\*\Downloads` dan `C:\Users\*\AppData\Local\Temp` pakai wildcard biar nutup **semua profil user**, bukan cuma `p.analyst`. Restart service:

```
NET STOP WazuhSvc
NET START WazuhSvc
```

### 2. Tunggu baseline scan

FIM butuh baseline scan pertama sebelum bisa detect perubahan — cek progress di log agent:

```
Get-Content "C:\Program Files\ossec-agent\ossec.log" -Tail 30 -Wait
# tunggu sampe ada baris "Ending syscheck scan"
```

### 3. Test manual

Bikin file dummy dengan ekstensi yang masuk `restrict` di salah satu folder yang dipantau:

```
echo test > C:\Users\%USERNAME%\Downloads\test-fim.exe
```

Cek Wazuh Dashboard — harus muncul alert **"File added to the system"** (rule `554`) buat path itu, dengan `syscheck.uname_after` + `audit.process` (dari `whodata`) nunjukin user/proses yang bikin file. Hapus file test:

```
del C:\Users\%USERNAME%\Downloads\test-fim.exe
```

> File dengan ekstensi di luar `restrict` (misal `test-fim.txt`) **sengaja gak akan** bikin alert — itu tanda restrict jalan bener.

### 4. Cek rule bawaan di Wazuh Manager (Dell)

Wazuh punya ruleset default lengkap buat FIM (`0550-fim_rules.xml`). Range `550`–`554` udah nutup kejadian dasar:

| Rule | Level | Kejadian |
|------|-------|----------|
| `554` | 5 | File **added** |
| `550` | 7 | File **modified** (checksum/integrity berubah) |

FIM itu **log stream terpisah** (decoder `syscheck`), jadi gak ada konflik decoder/rule kayak kasus `web-accesslog` di lab JS Attacks. Rule default udah cukup buat validasi awal.

Custom rule tambahan (misal: naikin severity kalau file `.lnk` double-extension nongol di Downloads — indikasi kuat phishing) didesain nanti berdasar temuan real, pola yang sama kayak lab-lab sebelumnya: **setup infra dulu, custom rule belakangan**.

---

## Verifikasi

✅ Confirmed live di run lab [Phishing via Malicious LNK](<../Labs/os-client/Win-7/Initial Access/Phishing via Malicious LNK (T1566.001 + T1204.002)/README.md>) (30 Sep 2026):

- **`554` (File added)** fire buat `c:\users\p.analyst\downloads\invoice_september.pdf.lnk` — `.lnk` lolos `restrict` walau namanya nyamar `.pdf`, `whodata` nunjukin proses `powershell.exe` yang naruh file.
- **`550` (File modified)** fire buat `c:\users\p.analyst\appdata\local\temp\update.exe` — payload di-drop di Temp, `whodata` nyambungin ke proses PowerShell yang sama (pid `3884`).

> Catatan: di run itu `update.exe` muncul sebagai `550` (modified) bukan `554` (added) karena file dengan nama sama udah ada dari run sebelumnya. Di environment bersih (snapshot dibalikin), drop pertama bakal jadi `554`.

---

## Catatan

Kerjaan ini jadi prerequisite buat lab [Phishing via Malicious LNK](<../Labs/os-client/Win-7/Initial Access/Phishing via Malicious LNK (T1566.001 + T1204.002)/README.md>) — layer FIM yang nangkep sisi artefak file (`.lnk` mendarat + payload di-drop), pelengkap rule Sysmon (`100601`/`100602`) yang nangkep sisi proses + network. Dua-duanya dikorelasi lewat `whodata` + `processGuid` yang nunjuk ke proses yang sama.
