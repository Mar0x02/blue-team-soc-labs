# Web-Server — Setup FIM/Syscheck (Direktori Upload DVWA)

## Tujuan

Aktifin **File Integrity Monitoring (FIM/syscheck)** Wazuh Agent di Web-Server (`10.10.10.10`, LAN1), khusus monitor direktori `hackable/uploads/` DVWA — buat lab [File Upload](../Labs/web-server-attack/file-upload/README.md).

Beda dari `access.log` (jejak request) atau auditd (jejak proses), FIM ngasih sinyal independen dari layer ketiga: **filesystem**. Hipotesis lab File Upload butuh ini karena inti serangannya adalah munculnya **file baru** (webshell) di direktori yang bisa diakses lewat web — sinyal ini idealnya ke-detect terlepas dari isi request upload (yang kemungkinan gak ke-log lengkap, mirip POST body Command Injection) maupun proses yang jalan belakangan.

---

## Prerequisites

- Web-Server base OS + DVWA sudah terinstall, direktori `hackable/uploads` sudah `chmod 777` — lihat [`dvwa-setup.md`](./dvwa-setup.md)
- Wazuh Agent di Web-Server sudah terinstall dan **status Active** — lihat [`web-server-wazuh-agent.md`](./web-server-wazuh-agent.md)
- auditd sudah terpasang (dari lab Command Injection) — dipakai buat `whodata` biar FIM alert nunjukin **siapa/proses apa** yang bikin file, bukan cuma "ada file baru" — lihat [`web-server-auditd-setup.md`](./web-server-auditd-setup.md)

---

## Step-by-Step

### 1. Tambah direktori ke `<syscheck>` (Wazuh Agent, Web-Server)

```bash
sudo nano /var/ossec/etc/ossec.conf
```

Cari block `<syscheck>` yang udah ada (biasanya isinya cuma default `<frequency>`), tambahin `<directories>` buat path upload DVWA:

```xml
<syscheck>
  <disabled>no</disabled>
  <frequency>43200</frequency>

  <directories check_all="yes" realtime="yes" whodata="yes">/var/www/html/hackable/uploads</directories>
</syscheck>
```

- `realtime="yes"` — deteksi langsung pas file muncul, gak nunggu scheduled scan (`frequency`)
- `whodata="yes"` — manfaatin auditd yang udah kepasang, biar alert nunjukin `uid`/`process` yang bikin file (bukan cuma "file X ditambahin")

Restart agent:

```bash
sudo systemctl restart wazuh-agent
```

### 2. Tunggu baseline scan

FIM butuh baseline scan pertama sebelum bisa detect perubahan — cek progress-nya di log agent:

```bash
sudo tail -f /var/ossec/logs/ossec.log
# tunggu sampe ada baris "Ending syscheck scan"
```

### 3. Test manual (belum lewat upload beneran)

```bash
sudo touch /var/www/html/hackable/uploads/test-fim.txt
```

Cek Wazuh Dashboard (atau `alerts.log` di Dell) — harus muncul alert **"File added"** buat path itu, dengan `syscheck.uname_after`/`audit.process` (kalau `whodata` jalan) nunjukin `www-data`/proses yang bikin file. Hapus file test:

```bash
sudo rm /var/www/html/hackable/uploads/test-fim.txt
```

### 4. Cek rule bawaan di Wazuh Manager (Dell)

Wazuh punya ruleset default lengkap buat FIM (`0550-fim_rules.xml` atau serupa) — beda dari kasus `web-accesslog` di lab JS Attacks, FIM adalah **log stream terpisah** (bukan HTTP access log), jadi gak ada konflik decoder/rule kayak yang kejadian sebelumnya. Rule default (`550`-`554` range, level 7 buat "File added") harusnya udah cukup buat validasi hipotesis awal.

Custom rule tambahan (misal: escalate severity spesifik kalau ekstensi file yang nongol `.php`/`.phtml` di direktori ini — indikasi kuat webshell) didesain nanti pas eksekusi lab File Upload beneran, sesuai temuan real (pola yang sama kayak lab-lab sebelumnya: setup infra dulu, custom rule belakangan berdasar hasil test).

---

## Verifikasi

✅ Test manual (`touch`/`rm` file) di `hackable/uploads/` confirmed nge-generate alert FIM "File added" di Wazuh Dashboard, `whodata` nunjukin proses yang bikin perubahan.

---

## Catatan

Kerjaan ini jadi prerequisite blocking buat lab [File Upload](../Labs/web-server-attack/file-upload/README.md) hipotesis #2 — apakah FIM bisa jadi sinyal deteksi independen (terlepas dari isi request maupun proses) buat serangan yang intinya "file baru muncul", bukan command yang dieksekusi (beda dari Command Injection) atau payload di URL (beda dari SQLi/XSS/LFI).
