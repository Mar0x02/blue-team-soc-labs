# Meterpreter Payload Execution & C2 Callback (T1071 + T1095) — Win7 Victim

## Tujuan

Simulasi tahap **command and control** di Win7 victim (`10.10.20.10`, LAN2): payload `update.exe` (`windows/meterpreter/reverse_tcp` bikinan msfvenom) yang udah mendarat di endpoint **dieksekusi**, lalu **konek balik** ke handler Metasploit di Kali (`192.168.43.111`) dan buka sesi meterpreter. Fokusnya: sinyal apa yang bisa ditangkap **Sysmon** (dan **Suricata** di jalur network) waktu payload jalan dan sesi C2 kebuka — sesuai MITRE ATT&CK **T1071 (Application Layer Protocol)** dan **T1095 (Non-Application Layer Protocol)**.

Ini **lanjutan langsung** dari lab [Phishing via Malicious LNK](<../../Initial Access/Phishing via Malicious LNK (T1566.001 + T1204.002)/README.md>). Di lab itu rantai berhenti terdokumentasi sebagai **gap**: FIM dan Sysmon nangkep sisi *delivery* dan *download* (`554`/`550`/`100601`/`100602`), tapi dua stage terakhir **lolos dari Wazuh** —

1. **Eksekusi `update.exe`** (`Start-Process`) gak jadi alert (Event 1 bawaan `61603` level 0).
2. **Callback meterpreter** gak ke-flag: koneksinya dari proses `update.exe` (bukan `powershell.exe`), jadi gak nyambung ke rule korelasi `100602` yang nyari proses eks-`100601`. Koneksi `:4000` yang kemarin kedeteksi itu **download**-nya, bukan sesi C2.

Lab ini fokus nutup dua gap itu: bikin **eksekusi payload dari lokasi gak wajar** (`%TEMP%`/`AppData`) dan **koneksi C2 dari proses non-browser** jadi sinyal yang kelihatan analis.

Sesuai filosofi lab: **deteksi dulu, bukan eksploitasi.**

---

## Prerequisites

- **Lab Phishing LNK udah dijalanin** — foothold + `update.exe` udah ada di `%TEMP%` Win7. Lihat [Phishing via Malicious LNK](<../../Initial Access/Phishing via Malicious LNK (T1566.001 + T1204.002)/README.md>).
- **Sysmon terpasang & jalan di Win7** — lihat [`win7-sysmon.md`](../../../../../Infrastructure/win7-sysmon.md). Deteksi bersandar ke **Event 1 (ProcessCreate)** buat eksekusi payload dan **Event 3 (NetworkConnect)** buat callback C2.
- **Wazuh Agent di Win7 Active** — lihat [`win7-wazuh-agent.md`](../../../../../Infrastructure/win7-wazuh-agent.md).
- **Suricata aktif di pfSense** (opsional, network layer) — lihat [`pfsense-suricata-setup.md`](../../../../../Infrastructure/pfsense-suricata-setup.md). Sesi reverse_tcp Win7 → Kali lewat pfSense WAN, jadi bisa keliatan di IDS.
- **Handler Metasploit di Kali** — `exploit/multi/handler` dengan payload `windows/meterpreter/reverse_tcp` yang cocok sama `update.exe`, nunggu koneksi balik.
- **Snapshot VM Win7** sebelum mulai, biar gampang balik ke state bersih (dan biar `update.exe` muncul sebagai file bersih, bukan sisa run lama).

---

## Step-by-Step

### 1. Siapkan handler di Kali

`update.exe` (payload `windows/meterpreter/reverse_tcp`) udah ada di `%TEMP%` Win7 dari lab LNK sebelumnya. Di Kali, `msfconsole` buka `exploit/multi/handler` dengan payload yang cocok, `LPORT 4444`, nunggu koneksi balik. Beda dari web server `:4000` di lab LNK (itu buat download) — `:4444` ini port callback meterpreter yang sebenarnya.

### 2. Skenario A — payload dijalanin ulang lewat chain LNK (parent: PowerShell)

Re-trigger chain yang sama kayak lab LNK (`Start-Process` dari dalam `-EncodedCommand` PowerShell yang di-spawn LNK). `update.exe` jalan dengan `parentImage` = `powershell.exe`.

### 3. Skenario B — payload dijalanin manual oleh user (parent: Explorer)

`p.analyst` double-click langsung `update.exe` yang udah nangkring di `AppData\Local\Temp` (tanpa lewat LNK/PowerShell lagi). `update.exe` jalan dengan `parentImage` = `explorer.exe` — simulasi user yang nemu/buka file itu sendiri.

Di kedua skenario, begitu `update.exe` jalan dia langsung connect balik ke handler Kali di `192.168.43.111:4444` dan buka sesi meterpreter.

---

## Verifikasi

Empat rule baru ditambah di `sysmon_rules.xml` (`100611`–`100614`), bertingkat:

| Rule | Level | Nangkep |
|------|-------|---------|
| `100611` | 8 | Executable jalan dari `Temp`/`AppData` (generic, Event 1) |
| `100612` | 10 | `100611` + `parentImage` = `powershell.exe` (lebih spesifik) |
| `100613` | 11 | Koneksi keluar dari exe di `Temp`/`AppData` (Event 3) |
| `100614` | 14 | Korelasi: `100613` + `100612` match `processGuid` yang sama (timeframe 120s) |

**Skenario A (parent PowerShell)** — `processGuid {AF48A474-0E09-...}`, ~09:57:29–31 UTC:

| # | Rule | Level | Apa |
|---|------|-------|-----|
| 1 | `100612` | 10 | `update.exe` (Temp) jalan, `parentImage` = `powershell.exe -EncodedCommand`, `parentCommandLine` nunjukin ulang chain `DownloadFile` + `Start-Process` dari LNK |
| 2 | `100614` | 14 (mail) | **CORRELATION fire** — `100612` + koneksi ke `192.168.43.111:4444` match `processGuid` sama |

![Process create update.exe dari PowerShell encoded](<./assets/rule 100612 process create powershell.png>)
![Network connect ke handler Kali :4444](<./assets/rule 100614 network connect kali.png>)

**Skenario B (parent Explorer)** — `processGuid {AF48A474-0FA7-...}`, ~10:04:23–24 UTC:

| # | Rule | Level | Apa |
|---|------|-------|-----|
| 1 | `100611` | 8 | `update.exe` (Temp) jalan, `parentImage` = `explorer.exe` — gak match kondisi `100612` (bukan spawn dari PowerShell) |
| 2 | `100613` | 11 | Koneksi keluar ke `192.168.43.111:4444` — fire sendiri |

Di run ini **`100614` gak fire**, karena `if_matched_sid`-nya nunjuk ke `100612` doang, dan `100612` gak pernah match di skenario B (parent-nya Explorer, bukan PowerShell). Jalur eksekusi manual — yang justru paling umum terjadi di real-world (user double-click file) — lolos dari korelasi high-confidence.

### Gap ketemu → rule 100615

Ditambah rule kembar `100614`, tapi nunjuk ke `100611` (bukan `100612`):

```xml
<rule id="100615" level="14" timeframe="120">
    <if_sid>100613</if_sid>
    <if_matched_sid>100611</if_matched_sid>
    <same_field>win.eventdata.processGuid</same_field>
    <description>CORRELATION: Same process executed from Temp/AppData AND opened C2 connection - $(win.eventdata.image)</description>
    ...
</rule>
```

`100614` dan `100611` saling melengkapi tanpa overlap: Wazuh cuma ngalerting rule paling spesifik di chain `if_sid` (jadi event yang match `100612` gak pernah tercatat sebagai match `100611` juga), jadi `100614` nangkep jalur PowerShell dan `100615` nangkep jalur manual/Explorer — dua-duanya nutup ke level 14 (mail).

**⚠️ `100615` belum tervalidasi live** — ditambah setelah run skenario B di atas, jadi belum ada alert nyata yang ngebuktiin dia fire. Secara logic seharusnya fire (kondisinya persis sama kayak `100614`, cuma beda `if_matched_sid`), tapi belum dicek ulang di dashboard.

### Batasan

- `100615` belum divalidasi live (lihat di atas).
- Deskripsi `100614` dan `100615` sama persis — di dashboard dua rule ini gak kebedain tanpa buka detail JSON (`parentImage`). Kosmetik, gak ngaruh ke fungsi deteksi.
