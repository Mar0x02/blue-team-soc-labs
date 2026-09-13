# Windows 7 — Install Sysmon (Legacy Version) + Integrasi Wazuh

## Tujuan

Install **Sysmon** di Win7 (`10.10.20.10`, LAN2) dan integrasikan log-nya ke Wazuh Agent yang udah terpasang, biar visibility endpoint victim ini gak cuma ngandelin Windows Event Log standar (Application/Security/System).

Beda dari WIN AD (lihat [`winad-sysmon.md`](./winad-sysmon.md)), Win7 **gak bisa pakai Sysmon versi terbaru**. Writeup ini mendokumentasikan jalur legacy yang beneran jalan di Windows 7 Professional 32-bit, termasuk kompromi coverage yang harus diterima.

---

## Prerequisites

- Win7 sudah punya **Wazuh Agent 4.13 terinstall dan Active** (`WIN7-VICTIM` muncul Active di Wazuh Dashboard) — lihat [`win7-wazuh-agent.md`](./win7-wazuh-agent.md)
- Akses **Administrator** di Win7 (local Administrator atau domain user yang di-add ke local Administrators)
- Koneksi internet dari Win7, atau kemampuan transfer file dari device lain (download manual — lihat Step 1)

---

## Kendala: Sysmon Versi Terbaru Gak Jalan di Win7

Sysmon rilisan sekarang cuma support Windows 8.1+ / Server 2012+. Kalau dipaksa install di Win7, driver-nya ditolak dengan error:

```
Windows cannot verify the digital signature for this file...
```

Ini bukan soal file corrupt — Sysmon modern ditandatangani pakai **SHA-2 code signing**, sementara Windows 7 tanpa update SHA-2 (KB4474419) gak bisa memverifikasi signature driver tersebut. Karena Win7 di lab ini sengaja dibiarkan sebagai **legacy victim** (gak di-patch penuh, biar realistis sebagai target), jalan keluarnya bukan nge-patch Win7 tapi **turun ke versi Sysmon lama** yang masih SHA-1 signed.

Sysinternals gak nyediain arsip versi lama secara resmi, jadi binary-nya diambil dari arsip komunitas:

```
https://github.com/whit3rabbit/sysmon-archive
```

Versi yang dipakai: **Sysmon 4.0**.

---

## Step 1 — Download Sysmon 4.0

Download manual lewat browser di Win7, atau transfer file dari device lain.

> **Catatan:** Win7 default cuma punya **PowerShell 2.0** yang gak support `Invoke-WebRequest` — gotcha yang sama kayak waktu install Wazuh Agent (lihat [`win7-wazuh-agent.md`](./win7-wazuh-agent.md) Step 2). Jadi command download dari `winad-sysmon.md` gak bisa dipakai di sini.

Ambil dari repo arsip di atas, extract, lalu masuk ke folder hasil extract.

Karena Win7 di lab ini **32-bit** (lihat [`win7-setup.md`](./win7-setup.md)), binary yang dipakai adalah `Sysmon.exe` — **bukan** `Sysmon64.exe` seperti di WIN AD.

---

## Step 2 — Install Sysmon Tanpa Config XML

```cmd
Sysmon.exe -accepteula -i
```

Perhatikan: **tanpa argumen config file**. Config `sysmonconfig-export.xml` dari SwiftOnSecurity yang dipakai di WIN AD **gak kompatibel** dengan Sysmon 4.0 — config itu ditulis untuk schema versi modern, sementara Sysmon 4.0 pakai schema jauh lebih lama dan bakal nolak file tersebut.

Konsekuensinya: Sysmon jalan pakai **default configuration**, yang coverage-nya lebih sempit daripada config SwiftOnSecurity. Detailnya di bagian [Batasan Coverage](#batasan-coverage) di bawah.

---

## Step 3 — Integrasi ke Wazuh Agent

Karena Win7 32-bit, path agent-nya `C:\Program Files\ossec-agent\` — **tanpa** ` (x86)` seperti di WIN AD yang 64-bit.

Buka `ossec.conf` pakai Notepad **as Administrator** (biar bisa save — file di `Program Files` butuh elevated privilege):

```cmd
notepad "C:\Program Files\ossec-agent\ossec.conf"
```

Tambahin block ini di dalam `<ossec_config>`:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Save, lalu restart Wazuh Agent. Nama service di Win7 adalah `WazuhSvc` (beda dari WIN AD yang pakai `Wazuh`):

```cmd
NET STOP WazuhSvc
NET START WazuhSvc
```

---

## Verifikasi

### 1. Sysmon service jalan

Nama service untuk build 32-bit adalah `Sysmon`, dan driver-nya `SysmonDrv` (dua-duanya dikonfirmasi dari output `Sysmon.exe -c`):

```powershell
Get-Service Sysmon
# Status harus Running
```

```powershell
sc.exe query SysmonDrv
# driver harus STATE : 4 RUNNING — kalau service jalan tapi driver mati, Sysmon gak ngerekam apa-apa
```

> **Wajib `sc.exe`, bukan `sc`.** Di PowerShell, `sc` adalah alias bawaan untuk `Set-Content` — bukan Service Control Manager. Kalau ditulis `sc query SysmonDrv`, command-nya gak pernah nyampe ke SCM dan output-nya kosong tanpa error yang jelas. Ini berlaku di semua versi PowerShell, bukan cuma PS 2.0 di Win7.

Alternatif kalau masih gak keluar hasil (driver gak muncul di `Get-Service` karena itu kernel driver, bukan Win32 service):

```powershell
Get-WmiObject Win32_SystemDriver -Filter "Name='SysmonDrv'" | Select-Object Name, State, Started
```

### 2. Event Sysmon tercatat di local Event Log

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
```

Bisa juga dicek lewat GUI: **Event Viewer → Applications and Services Logs → Microsoft → Windows → Sysmon → Operational**.

### 3. Event ID apa aja yang beneran tercatat

Berguna buat tahu coverage riil dari default config:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 500 |
  Group-Object Id |
  Select-Object Name, Count |
  Sort-Object Name
```

### 4. Wazuh Agent baca channel Sysmon tanpa error

```cmd
notepad "C:\Program Files\ossec-agent\ossec.log"
```

Cari baris yang nyebut `Microsoft-Windows-Sysmon/Operational`. Kalau ada error semacam *"Could not subscribe"* atau *"channel not found"*, berarti nama channel salah atau Sysmon belum jalan.

### 5. Log nyampe ke Wazuh Manager

Dari Wazuh Dashboard → **Discover**, query pakai **DQL** (operator `and`, bukan `&&`):

```
agent.name: "WIN7-VICTIM" and data.win.system.channel: "Microsoft-Windows-Sysmon/Operational"
```

Kalau muncul hasil, chain lengkap **Sysmon → Windows Event Log → Wazuh Agent → Wazuh Manager → Dashboard** confirmed jalan.

---

## Batasan Coverage

Kombinasi **versi lama + tanpa config XML** bikin visibility Win7 jauh di bawah WIN AD. Ini perlu dicatat eksplisit supaya gak salah baca hasil deteksi nanti — absennya event bukan berarti serangannya gak kejadian, bisa jadi Sysmon-nya memang gak ngerekam kategori itu.

**Batasan dari versi 4.0.** Sysmon 4.0 (rilis 28 April 2016) pakai **`schemaversion="2.01"`** (dikonfirmasi dari output `Sysmon.exe -? config`: *"current schema is version: 2.01"*) dan cuma punya event berikut:

| Event ID | Kategori | Filter tag di config |
|----------|----------|----------------------|
| 1 | ProcessCreate | `ProcessCreate` |
| 2 | FileCreateTime | `FileCreateTime` |
| 3 | NetworkConnect | `NetworkConnect` |
| 4 | Sysmon service state changed | — (selalu dicatat) |
| 5 | ProcessTerminate | `ProcessTerminate` |
| 6 | DriverLoad | `DriverLoad` |
| 7 | ImageLoad | `ImageLoad` |
| 8 | CreateRemoteThread | `CreateRemoteThread` |
| 9 | RawAccessRead | `RawAccessRead` |
| 255 | Sysmon error | — (selalu dicatat) |

Semua event di luar daftar itu **gak ada sama sekali** di Win7 — termasuk `ProcessAccess` yang sering diasumsikan ada karena nomornya kecil:

| Event ID | Kategori | Versi Sysmon |
|----------|----------|--------------|
| 10 | ProcessAccess | setelah v4.0 (v5.x/v6.x) |
| 11 | FileCreate | v5.0+ |
| 12, 13, 14 | Registry events | v5.0+ |
| 15 | FileCreateStreamHash | setelah v4.0 |
| 17, 18 | Named pipe | v6.0+ |
| 19, 20, 21 | WMI events | v6.x+ |
| 22 | DNS query | v10.0+ |
| 23, 26 | FileDelete | v11.0+ |
| 25 | Process tampering | v13.0+ |

> **Konsekuensi paling penting: absennya event 10 (`ProcessAccess`).** Itu event yang dipakai buat mendeteksi proses yang ngebuka memory proses lain — basis deteksi **credential dumping via LSASS** (Mimikatz, `procdump lsass.exe`). Di `WIN7-VICTIM` deteksi itu **gak mungkin lewat Sysmon**, harus lewat jalur lain (Security log 4656/4663 dengan SACL di `lsass.exe`, atau deteksi berbasis process creation dari tool-nya).

**Batasan dari default config.** Ini bukan dugaan — `Sysmon.exe -c` ngedump state default apa adanya:

```
Current configuration:
 - Service name:                Sysmon
 - Driver name:                 SysmonDrv
 - HashingAlgorithms:           SHA1
 - Network connection:          disabled
 - Image loading:               disabled

No rules installed
```

Tiga hal yang dikonfirmasi dari situ:

| Item | State default | Dampak |
|------|---------------|--------|
| Network connection (event 3) | **disabled** | Gak ada visibility koneksi outbound sama sekali |
| Image loading (event 7) | **disabled** | Gak ada visibility DLL/module load |
| HashingAlgorithms | **SHA1 saja** | Gak ada SHA256 — hash dari ProcessCreate kurang optimal buat enrichment VirusTotal |
| Rules | **No rules installed** | Event yang aktif dicatat tanpa filter sama sekali |

Karena cuma dua kategori itu yang berstatus *disabled*, event sisanya **aktif by default** — jadi baseline yang sekarang tercatat di Win7 adalah event **1, 2, 4, 5, 6, 8, 9, 255**.

Dua kategori yang disabled itu punya flag enable tersendiri:

| Flag | Fungsi (dari help v4.0) | Event |
|------|--------------------------|-------|
| `-n [<process,...>]` | *Log network connections* | 3 |
| `-l [<process,...>]` | *Log loading of modules* | 7 |

Dua flag itu bisa dibatasi ke proses tertentu (`-n <process,...>`) kalau volume log kelewat ramai.

> **Gotcha penamaan:** output `-c` nulis **`HashingAlgorithms`**, tapi elemen di config file namanya **`HashAlgorithms`** (tanpa "ing") — sesuai help `-h` dan contoh config bawaan. Jangan ikut ejaan dari output `-c` waktu nulis config.

**Soal config XML.** Sysmon 4.0 butuh config dengan root `<Sysmon schemaversion="2.01">`. Gak ada config komunitas yang maintained untuk schema sekuno itu — SwiftOnSecurity maupun Olaf Hartong dua-duanya nargetin schema 4.x modern, jadi satu-satunya jalan adalah tulis manual.

Referensi schema diambil dari binary-nya sendiri, bukan sumber luar:

```cmd
Sysmon.exe -? config    :: format config + daftar filter tag + filter condition
Sysmon.exe -c           :: dump config yang sedang aktif
```

> **Catatan:** flag `-s` **gak ada** di Sysmon 4.0 — kalau dijalanin output-nya cuma usage/help, bukan schema dump. Flag itu baru ada di versi yang lebih baru.

**Filter condition yang valid di schema 2.01** (semua case-insensitive):

| Condition | Arti |
|-----------|------|
| `is` | Default, nilai sama persis |
| `is not` | Nilai beda |
| `contains` | Field memuat nilai ini |
| `excludes` | Field tidak memuat nilai ini |
| `begin with` | Field diawali nilai ini |
| `end with` | Field diakhiri nilai ini |
| `less than` | Perbandingan leksikografis kurang dari |
| `more than` | Perbandingan leksikografis lebih dari |
| `image` | Match path image (full path atau nama file saja) |

**Semantik filter yang wajib dipahami sebelum nulis config:**

- `onmatch="include"` → **hanya** event yang match yang dicatat. `onmatch="exclude"` → semua dicatat **kecuali** yang match.
- Tag kosong itu bermakna: `<ProcessTerminate onmatch="include" />` (include tanpa rule) = **gak nyatat apa-apa**, sedangkan `<ProcessCreate onmatch="exclude" />` (exclude tanpa rule) = **nyatat semua**.
- Kalau satu tag punya rule include **dan** exclude, **exclude menang**.
- Dalam satu rule: kondisi pada **field yang sama** = **OR**, kondisi pada **field berbeda** = **AND**.
- Elemen hash bernama `HashAlgorithms`, nilai `sha1` / `md5` / `sha256` / `imphash` / `*`, default `SHA1`.
- Schema 2.01 **belum punya `<RuleGroup>`** — itu konstruksi schema 4.x. Semua filter tag langsung di bawah `<EventFiltering>`.

**Implikasi ke detection engineering:** Sigma rules dari `SigmaHQ/sigma` yang ngandelin event 11/12-14/22 **gak akan pernah match** di `WIN7-VICTIM`. Buat endpoint ini, fokus ke rule yang berbasis **event 1 (Process Create)** — parent-child process relationship, command line — karena itu yang paling kuat tersedia di sini.

---

## Config Custom untuk Schema 2.01 (Opsional)

Default config cukup buat mulai, tapi punya dua kelemahan: event 3 (network connection) gak aktif, dan `ProcessTerminate` nyampah tanpa nilai deteksi. Config di bawah nyusun ulang coverage sesuai prioritas deteksi endpoint victim, pakai **hanya elemen dan field yang dikonfirmasi ada di schema 2.01**.

Simpan sebagai `sysmonconfig-win7.xml` di Win7:

```xml
<Sysmon schemaversion="2.01">
  <HashAlgorithms>*</HashAlgorithms>
  <EventFiltering>
    <ProcessCreate onmatch="exclude" />
    <NetworkConnect onmatch="exclude" />
    <CreateRemoteThread onmatch="exclude" />
    <RawAccessRead onmatch="exclude" />
    <FileCreateTime onmatch="exclude" />
    <DriverLoad onmatch="exclude">
      <Signature condition="contains">microsoft</Signature>
      <Signature condition="contains">windows</Signature>
    </DriverLoad>
    <ProcessTerminate onmatch="include" />
  </EventFiltering>
</Sysmon>
```

Karena Win7 gak punya cara gampang transfer file (PowerShell 2.0, gak ada `Invoke-WebRequest`), paling praktis bikin file-nya langsung dari PowerShell pakai here-string — paste blok berikut apa adanya:

```powershell
@'
<Sysmon schemaversion="2.01">
  <HashAlgorithms>*</HashAlgorithms>
  <EventFiltering>
    <ProcessCreate onmatch="exclude" />
    <NetworkConnect onmatch="exclude" />
    <CreateRemoteThread onmatch="exclude" />
    <RawAccessRead onmatch="exclude" />
    <FileCreateTime onmatch="exclude" />
    <DriverLoad onmatch="exclude">
      <Signature condition="contains">microsoft</Signature>
      <Signature condition="contains">windows</Signature>
    </DriverLoad>
    <ProcessTerminate onmatch="include" />
  </EventFiltering>
</Sysmon>
'@ | Out-File -FilePath "$env:USERPROFILE\Desktop\sysmonconfig-win7.xml" -Encoding ASCII
```

`-Encoding ASCII` penting — default `Out-File` di PowerShell nulis UTF-16 dengan BOM, dan itu bisa bikin parser XML Sysmon nolak file-nya.

Apply ke Sysmon yang udah terpasang (gak perlu uninstall/reinstall):

```cmd
Sysmon.exe -c sysmonconfig-win7.xml
```

Verifikasi config kepakai:

```cmd
Sysmon.exe -c
```

### Alasan tiap keputusan

| Tag | Setting | Alasan |
|-----|---------|--------|
| `ProcessCreate` | exclude kosong = **catat semua** | Event paling bernilai di Win7. Karena event 10 gak ada, event 1 jadi tulang punggung deteksi di host ini — jangan difilter. |
| `NetworkConnect` | exclude kosong = **catat semua** | Satu-satunya jalan lihat koneksi outbound → basis deteksi C2 beacon & lateral movement. Volume di lab kecil, jadi gak perlu filter port seperti contoh bawaan Sysmon. |
| `CreateRemoteThread` | exclude kosong | Deteksi process injection. Volume rendah, nilai deteksi tinggi. |
| `RawAccessRead` | exclude kosong | Deteksi raw disk access — dipakai buat baca file terkunci (SAM, NTDS). Volume rendah. |
| `FileCreateTime` | exclude kosong | Deteksi **timestomping** (anti-forensik). Volume sedang. |
| `DriverLoad` | exclude Microsoft/Windows signed | Driver pihak ketiga di Win7 patut dicurigai (rootkit). Filter signature mengikuti contoh resmi di help Sysmon. |
| `ProcessTerminate` | **include kosong = gak dicatat** | Nilai deteksinya kecil tapi volumenya besar. Pola `include` kosong ini diambil dari contoh resmi di help (*"Do not log process termination"*). |
| `ImageLoad` | **tag sengaja dihilangkan** | Volume paling besar dari semua event dan Win7 cuma RAM 2GB. Kalau nanti butuh deteksi DLL hijacking, tambahkan tag `ImageLoad` atau jalankan `Sysmon.exe -l`. |

`<HashAlgorithms>*</HashAlgorithms>` ngasih semua algoritma sekaligus (SHA1, MD5, SHA256, IMPHASH). SHA256 dibutuhkan buat enrichment VirusTotal di pipeline AI, dan IMPHASH berguna buat korelasi malware family. Kalau volume log jadi masalah, sempitkan ke `md5,sha256`.

> **Cara test yang decisive:** habis apply config, jalanin `Sysmon.exe -c` lagi dan lihat baris **`Network connection:`**. Kalau berubah dari `disabled` jadi `enabled`, berarti tag `<NetworkConnect>` di config memang cukup buat ngaktifin event 3. Kalau masih `disabled`, tambahin `Sysmon.exe -n`. Ini lebih cepat dan lebih pasti daripada nunggu event muncul di Event Viewer — baris `Image loading:` juga bisa dipakai buat ngecek hal yang sama soal event 7.

---

## Troubleshooting

| Masalah | Kemungkinan Penyebab | Solusi |
|---------|----------------------|--------|
| `Windows cannot verify the digital signature for this file...` | Sysmon versi modern (SHA-2 signed) gak didukung Win7 tanpa KB4474419 | Turun ke Sysmon versi lama (4.0) dari arsip komunitas — lihat bagian Kendala di atas |
| Config XML ditolak / error waktu `-i <config>` | Config SwiftOnSecurity pakai schema modern, gak kompatibel Sysmon 4.0 | Install tanpa config (`Sysmon.exe -accepteula -i`), terima default config |
| `Sysmon64.exe` gak ada / gak mau jalan | Win7 lab ini 32-bit | Pakai `Sysmon.exe` (dan service-nya bernama `Sysmon`, bukan `Sysmon64`) |
| `Get-Service Sysmon64` → error not found | Sama seperti di atas, naming 32-bit | `Get-Service Sysmon` |
| `Invoke-WebRequest : command not found` | Win7 default PowerShell 2.0 | Download manual lewat browser atau transfer dari device lain (Step 1) |
| `sc query SysmonDrv` gak ada output sama sekali | Di PowerShell, `sc` = alias `Set-Content`, bukan Service Control Manager | Pakai `sc.exe query SysmonDrv`, atau `Get-WmiObject Win32_SystemDriver -Filter "Name='SysmonDrv'"` |
| Driver `SysmonDrv` gak muncul di `Get-Service` | `Get-Service` cuma nampilin Win32 service, bukan kernel driver | Pakai `sc.exe query` atau WMI `Win32_SystemDriver` |
| `Sysmon.exe -s` cuma keluar usage/help, bukan schema | Flag `-s` gak ada di Sysmon 4.0 | Pakai `Sysmon.exe -? config` buat info config, `Sysmon.exe -c` buat dump config aktif |
| `NET STOP Wazuh` gagal, service not found | Nama service Wazuh Agent beda per OS | Win7 pakai `WazuhSvc`. Kalau ragu: `Get-Service \| Where-Object {$_.Name -like "*wazuh*"}` |
| Channel Sysmon gak muncul di Dashboard, tapi event ada lokal | Block `<localfile>` salah tempat atau agent belum restart | Pastikan block ada di dalam `<ossec_config>`, restart `WazuhSvc`, cek `ossec.log` |
| Path `C:\Program Files (x86)\ossec-agent` gak ada | Win7 32-bit gak punya folder `Program Files (x86)` | Pakai `C:\Program Files\ossec-agent\` |

---

## Catatan Keamanan Lab

- **Binary dari arsip pihak ketiga.** Sysmon 4.0 di sini diambil dari repo komunitas (`whit3rabbit/sysmon-archive`), bukan dari Sysinternals resmi — karena Microsoft gak nyediain arsip versi lama. Untuk lab terisolasi ini risikonya diterima, tapi praktik yang benar adalah verifikasi signature binary-nya (`Get-AuthenticodeSignature .\Sysmon.exe`) dan pastikan publisher-nya tetap **Microsoft Corporation** sebelum dipakai. Jangan pernah pakai pola ini di environment produksi.
- **Sysmon 4.0 udah lama gak di-support.** Gak ada bug fix maupun security update. Ini konsisten dengan peran Win7 sebagai legacy victim di lab, dan justru mencerminkan kondisi nyata di banyak environment enterprise yang masih megang endpoint lama — tapi sadari bahwa toolnya sendiri bagian dari attack surface.
- **Default config = noise rendah, coverage rendah.** Buat skenario lab yang butuh visibility lebih, aktifkan `-n` (network connection) dulu karena itu yang paling sering dibutuhkan dalam deteksi C2 / lateral movement.
