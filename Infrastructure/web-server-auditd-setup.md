# Web-Server — Install auditd + Integrasi Wazuh

## Tujuan

Pasang **auditd** (Linux Audit Framework) di Web-Server (`10.10.10.10`, LAN1) dan integrasikan ke **Wazuh Agent** yang udah terpasang, biar Wazuh punya visibility ke **process execution** — nutup blind spot yang ketemu di lab [Command Injection](../Labs/web-server-attack/command-injection/README.md): reverse shell berbasis **LOLBin** (`sh -i`, `nc`, `mkfifo`) kebukti gak ke-detect sama sekali, walaupun prosesnya keliatan jelas di `htop`. Wazuh Agent default cuma baca log aplikasi/FIM, gak punya cara buat tau ada proses baru yang di-spawn — auditd yang ngisi gap itu, dengan capture syscall level (`execve`, `connect`, dll) langsung dari kernel.

---

## Prerequisites

- Web-Server base OS + DVWA sudah terinstall — lihat [`web-server-setup.md`](./web-server-setup.md) dan [`dvwa-setup.md`](./dvwa-setup.md)
- Wazuh Agent di Web-Server sudah terinstall dan **status Active** — lihat [`web-server-wazuh-agent.md`](./web-server-wazuh-agent.md)
- Referensi kesimpulan lab yang jadi basis kerjaan ini — lihat section ["Kesimpulan Akhir"](../Labs/web-server-attack/command-injection/README.md#kesimpulan-akhir--sql-injection-vs-command-injection) di writeup Command Injection

---

## Step-by-Step

### 1. Install auditd

```bash
sudo apt install auditd
```

### 2. Tambah audit rule — capture `execve` khusus `www-data` (uid=33)

Daripada nebak-nebak nama binary LOLBin satu-satu (`sh`, `nc`, `python3`, ...), rule ini filter berdasarkan **UID `www-data`** — secara normal `www-data` gak pernah perlu spawn proses baru, jadi apapun yang dia jalanin patut dicurigai.

```bash
sudo nano /etc/audit/rules.d/audit.rules
```

Isi (rule lengkap + rasional-nya juga disalin ke [`Detection-Engineer/auditd-trigger-rule/audit.rules`](../Detection-Engineer/auditd-trigger-rule/audit.rules) biar ke-version-control):

```
-a always,exit -F arch=b64 -S execve -F uid=33 -k www_data_exec
-a always,exit -F arch=b32 -S execve -F uid=33 -k www_data_exec
```

Load rule dan restart service:

```bash
sudo augenrules --load
sudo systemctl restart auditd
```

Cek rule udah aktif:

```bash
sudo auditctl -l
```

Test manual (belum lewat Wazuh, langsung dari `ausearch`):

```bash
sudo ausearch -k www_data_exec
```

### 3. Konfigurasi Wazuh Agent baca `audit.log`

Edit `/var/ossec/etc/ossec.conf` di Web-Server, tambahin `<localfile>` (sejajar block lain, di dalam `<ossec_config>`):

```xml
<localfile>
  <log_format>audit</log_format>
  <location>/var/log/audit/audit.log</location>
</localfile>
```

```bash
sudo systemctl restart wazuh-agent
```

### 4. Cek decoder/rule di Wazuh Manager (Dell)

Wazuh punya ruleset default buat auditd, konfirmasi lokasinya di Dell:

```bash
sudo ls /var/ossec/ruleset/rules | grep "auditd"
# 0365-auditd_rules.xml
```

Ruleset default (`0365-auditd_rules.xml`) cuma nyampe ke rule dasar `80700` (level 0, "Audit: messages grouped") — gak ada rule bawaan yang nge-generate alert spesifik buat key custom kayak `www_data_exec`. Jadi perlu **custom rule tambahan**, disimpen di [`Detection-Engineer/wazuh-rules/auditd_lolbin_rules.xml`](../Detection-Engineer/wazuh-rules/auditd_lolbin_rules.xml):

```xml
<group name="auditd,lolbin,command_injection,">

  <rule id="100300" level="12">
    <if_sid>80700</if_sid>
    <field name="audit.key">www_data_exec</field>
    <description>LOLBin: www-data (Apache) menjalankan proses baru "$(audit.command)" - indikasi command injection</description>
    <mitre>
      <id>T1059</id>
    </mitre>
  </rule>

</group>
```

Copy ke `/var/ossec/etc/rules/` di Dell, test & restart:
```bash
sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager
```

> **Gotcha:** Rule ini pakai `<if_sid>80700</if_sid>` buat chaining ke rule dasar auditd — dan itu yang akhirnya jadi versi final yang jalan. Sempet dicoba ganti ke `<decoded_as>auditd</decoded_as>` (skip chaining, langsung match nama decoder) berdasarkan [laporan bug komunitas](https://github.com/wazuh/wazuh/discussions/20766) soal inkonsistensi `if_sid` di `wazuh-logtest`, tapi versi `decoded_as` ini malah **regresi** — `wazuh-logtest` cuma nunjukin match ke rule dasar `80700` doang (gak nembus ke `100300`), gak match sama sekali. Balik lagi ke `if_sid`.
>
> Sempet juga stuck lama: `if_sid` udah lolos test manual `wazuh-logtest` (`Alert to be generated`, level 12), tapi **anehnya gak pernah kebentuk alert di `alerts.log`/Dashboard pas traffic beneran** — walaupun data mentahnya udah confirmed nyampe ke `archives.log`. Udah dicek rule syntax, manager restart, ossec.log (gak ada error/drop), CDB list `audit-keys` (ternyata itu spesifik buat rule bawaan FIM whodata `80780-80789`/`80792`, gak relevan ke custom rule) — semua clear tapi tetep gak alert. Solusinya ternyata **restart penuh seluruh sistem (bukan cuma `wazuh-manager`)** — kemungkinan besar cuma state/proses yang nyangkut, bukan soal rule XML-nya. Kalau ketemu gejala serupa (logtest sukses, live gak pernah alert, semua config udah bener), coba restart penuh dulu sebelum ngoprek rule lebih jauh.

---

## Verifikasi

✅ **Selesai** — replay payload command injection (`;id`, `;whoami`) lewat form DVWA, alert `Rule: 100300 (level 12)` muncul di `alerts.log` dan Wazuh Dashboard, dengan `audit.command` nunjukin proses yang di-spawn `www-data` (`sh`, `ping`, `id`/`whoami`/`ls`). Pipeline auditd→Wazuh Agent→Wazuh Manager→alert confirmed jalan end-to-end.

---

## Catatan

Kerjaan ini jalan bareng [`pfsense-suricata-setup.md`](./pfsense-suricata-setup.md) sebagai dua data source baru yang jadi keputusan arah Detection Engineering lab: auditd nutup blind spot **process execution** di endpoint, Suricata nutup blind spot **network traffic** independen dari log aplikasi. auditd dikerjain duluan karena effort-nya lebih kecil (single endpoint, config yang udah ada) dan langsung nutup gap yang paling nyata kebukti (reverse shell LOLBin).
