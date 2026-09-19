# Scheduled Task/Job: Scheduled Task (T1053.005) — Win7 Victim

## Tujuan

Simulasi **persistence via Scheduled Task** di Win7 victim (`10.10.20.10`, LAN2) sesuai MITRE ATT&CK **T1053.005**, lalu amati sinyal apa yang bisa ditangkap **Sysmon** dan **Windows Security log** di endpoint ini.

Ini lanjutan dari lab [T1059.001 PowerShell](<../../Execution/Command and Scripting Interpreter (T1059.001 - PowerShell)/README.md>). Di lab itu, PowerShell cuma jalan sekali. Di lab ini, attacker pasang PowerShell sebagai scheduled task yang jalan **otomatis tiap logon**, jadi aksesnya tetap ada walaupun host di-reboot atau user logoff. Tahap ini masih pakai payload dummy (`Write-Host`), fokusnya ke momen **task dibuat**.

Ini lab **assume-breach**. Titik berangkatnya adalah asumsi attacker udah bisa ngetik command di Win7 (disimulasikan dengan ngetik manual di `cmd.exe`). Fokusnya **deteksi**: jejak apa yang muncul waktu task dibuat, dan seberapa jauh SIEM kita bisa lihat.

Sesuai filosofi lab: **deteksi dulu, bukan eksploitasi.**

---

## Prerequisites

- **Sysmon terpasang & jalan di Win7** — lihat [`win7-sysmon.md`](../../../../../Infrastructure/win7-sysmon.md).
- **Wazuh Agent di Win7 Active** — lihat [`win7-wazuh-agent.md`](../../../../../Infrastructure/win7-wazuh-agent.md).
- **Command Prompt dengan hak Administrator** di Win7. `auditpol` dan `schtasks /ru SYSTEM` butuh elevated privilege.

---

## Step-by-Step

### 1. Cek audit policy buat event pembuatan scheduled task

Windows nyatet pembuatan scheduled task sebagai **Security Event ID 4698** ("A scheduled task was created"). Tapi event ini cuma ditulis kalau subcategory audit **Other Object Access Events** aktif. Cek dulu:

```cmd
auditpol /get /subcategory:"Other Object Access Events"
```

Di Win7 lab ini hasilnya `No Auditing`, artinya 4698 gak akan pernah ditulis. Aktifkan audit untuk event sukses:

```cmd
auditpol /set /subcategory:"Other Object Access Events" /success:enable
```

Cek ulang, setting-nya harus berubah jadi `Success`.

### 2. Cek service Task Scheduler jalan

```cmd
sc query schedule
```

`STATE` harus `4 RUNNING`. Kalau service ini mati, task gak bisa dibuat maupun dijalankan.

### 3. Cek channel Security di-collect Wazuh Agent

Buka config agent:

```cmd
notepad "C:\Program Files\ossec-agent\ossec.conf"
```

Pastikan ada `localfile` buat channel Security. Kalau belum ada, tambahkan:

```xml
<localfile>
  <location>Security</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Di lab ini channel Security udah ada, dan dilengkapi `<query>` yang **membuang** beberapa Event ID yang noisy: `5145, 5156, 5447, 4656, 4658, 4663, 4660, 4670, 4690, 4703, 4907, 5152, 5175`. **4698 gak ada di daftar itu**, jadi tetap dikirim ke Manager. Kalau nanti nambah filter sendiri, pastikan 4698 gak ikut ke-exclude.

![auditpol, sc query, dan schtasks /create di cmd](<./assets/schtask.png>)

### 4. Buat scheduled task

Dari `cmd.exe` (assume-breach: attacker udah bisa ngetik di sini):

```cmd
schtasks /create /tn "WindowsUpdateCheck" /tr "powershell.exe -NoProfile -WindowStyle Hidden -Command \"Write-Host 'Persistence task executed - Lab Test'\"" /sc onlogon /ru SYSTEM /f
```

| Parameter | Fungsi | Kenapa mencurigakan |
|-----------|--------|---------------------|
| `/tn "WindowsUpdateCheck"` | Nama task | Sengaja dibuat mirip task Windows yang sah (masquerading) |
| `/tr "powershell.exe ..."` | Command yang dijalankan task | PowerShell dengan `-NoProfile -WindowStyle Hidden`, jalan tanpa jendela |
| `/sc onlogon` | Trigger: tiap ada user logon | Inti persistence, jalan ulang tanpa attacker perlu ngetik lagi |
| `/ru SYSTEM` | Jalan sebagai `NT AUTHORITY\SYSTEM` | Privilege tertinggi di host |
| `/f` | Timpa task dengan nama sama tanpa konfirmasi | Bikin command bisa diulang tanpa prompt |

Output yang diharapkan:

```
SUCCESS: The scheduled task "WindowsUpdateCheck" has successfully been created.
```

---

## Verifikasi

### A. Task terdaftar di Win7

```cmd
schtasks /query /tn "WindowsUpdateCheck" /v /fo list
```

Field kunci dari output-nya:

| Field | Nilai |
|-------|-------|
| `TaskName` | `\WindowsUpdateCheck` |
| `Author` | `Administrator` |
| `Task To Run` | `powershell.exe -NoProfile -WindowStyle Hidden -Command "Write-Host ..."` |
| `Run As User` | `SYSTEM` |
| `Schedule Type` | `At logon time` |
| `Scheduled Task State` | `Enabled` |

![schtasks /query hasil task WindowsUpdateCheck](<./assets/schtask success create.png>)

### B. Event 4698 masuk Wazuh, tapi event 1 gak jadi alert

Setelah audit policy aktif, pembuatan task menghasilkan **Security 4698** di Wazuh. Rule bawaan yang menangkap adalah **`60228`**, level **4**.

Proses `schtasks.exe` yang bikin task itu juga kerekam Sysmon sebagai **event 1** (Process Create), lengkap dengan command line `/create ... /tr ...`. Tapi awalnya event ini **gak muncul sebagai alert**. Penyebabnya sama dengan lab T1059: rule bawaan Sysmon event 1 (`61603`) itu level 0, jadi event berhenti di situ dan gak masuk `wazuh-alerts-*`.

Padahal event 1 justru lebih kaya dari 4698. Di event 1 kelihatan **siapa yang manggil** (`parentImage` `cmd.exe`) dan **command line utuh**, jadi analis bisa langsung lihat payload yang dipasang di `/tr`.

### C. Custom rule 100605 — schtasks bikin task yang jalanin PowerShell

Rule turunan `61603` yang naikin event 1 `schtasks.exe` jadi alert. Disimpan di repo: [`Detection-Engineer/wazuh/rule/sysmon_rules.xml`](../../../../../Detection-Engineer/wazuh/rule/sysmon_rules.xml).

```xml
<rule id="100605" level="6">
    <if_sid>61603</if_sid>
    <field name="win.system.eventID" type="pcre2">^1$</field>
    <field name="win.eventdata.image" type="pcre2">(?i)\\schtasks\.exe$</field>
    <field name="win.eventdata.parentImage" type="pcre2">(?i)(?:powershell|cmd)\.exe$</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)schtasks(?:\.exe)?\W+[/-](?:create|change)\b</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)/tr\s+\S*(?:powershell|pwsh)</field>
    <description>Sysmon: Suspicious schtasks execution detected</description>
    <mitre>
        <id>T1053.005</id>
    </mitre>
    <group>scheduled_task,</group>
</rule>
```

| Field | Fungsi |
|-------|--------|
| `image` `\\schtasks\.exe$` | Proses yang dibuat adalah `schtasks.exe` |
| `parentImage` `(powershell\|cmd)\.exe$` | Dipanggil dari shell, pola eksekusi manual/scripted |
| `commandLine` `schtasks ... /create\|/change` | Bikin task baru atau ngubah action task yang udah ada. `\W+` supaya tetap match walaupun schtasks dipanggil pakai full path yang dikutip. `[/-]` nutup bentuk `-create` |
| `commandLine` `/tr\s+\S*(powershell\|pwsh)` | Action task-nya menjalankan PowerShell |

**Gotcha: tanda kutip di nilai field eventchannel.** Versi pertama rule ini pakai `\/tr\s+['"]?...powershell` dan **gak pernah match**. Decoder eventchannel nyimpen tanda kutip di nilai field **pakai backslash di depannya**, jadi yang dilihat rule engine adalah:

```
/tr \"powershell.exe -NoProfile ...
```

Karakter setelah spasi itu `\`, bukan `"`, jadi `['"]?` gak bisa nelen dan `powershell` gak ketemu. Ini masih satu keluarga dengan backslash dobel di field `image` (`C:\\Windows\\System32\\...`) yang ketemu di lab T1059. Fix-nya `\S*`, yang nelen apapun yang nempel sebelum nama program (`\"`, `'`, atau full path).

**Gak bentrok sama rule PowerShell `100601`/`100603`.** Command line schtasks bisa aja berisi `DownloadString` atau blob base64 kalau payload-nya cradle, tapi dua rule itu mensyaratkan `image` `powershell.exe`. Di event ini `image`-nya `schtasks.exe`.

**Batasan:** filter `parentImage` bikin rule ini buta kalau `schtasks.exe` dipanggil dari proses lain (`wscript.exe`, `mshta.exe`, `wmiprvse.exe`, atau binary malware).

### D. Hasil — alert live di Wazuh Dashboard

Setelah rule dipasang di Dell + restart `wazuh-manager`, command di Step 4 dijalankan ulang. Di Dashboard muncul dua alert berurutan dari `WIN7-VICTIM`: **event 1 dulu, baru 4698**.

| Masuk Manager (WIB) | Event | Rule | Detail |
|---------------------|-------|------|--------|
| 2026-09-20 00:02:40.635 | Sysmon 1 — Process Create | `100605` | `schtasks.exe` (PID 2984, GUID `{AF48A474-C026-6AAE-0000-00100A511E00}`), `UtcTime` 2026-09-19 17:02:30.973 (= 00:02:30.973 WIB) |
| 2026-09-20 00:02:41.622 | Security 4698 — scheduled task created | `60228` | Subject `LAB\Administrator` (SID berakhiran `-500`) |

Urutannya masuk akal. `schtasks.exe` harus jalan dulu (event 1) sebelum Task Scheduler mendaftarkan task-nya dan Windows menulis 4698.

![Alert event 1 (100605) dan 4698 (60228) di Wazuh Dashboard](<./assets/wazuh.png>)

> **Catatan evidence:** screenshot cmd (`schtask.png`, 22:24) dan screenshot Dashboard (`wazuh.png`, 00:02) berasal dari **run yang berbeda**. Task yang sama dibuat ulang (`/f` menimpa task lama) setelah rule `100605` dipasang. Command-nya identik.

---

## Kesimpulan

Pembuatan scheduled task sebagai mekanisme persistence di Win7 **bisa dideteksi dari dua sumber**:

- **Security 4698**. Butuh audit policy `Other Object Access Events` diaktifkan dulu, karena default-nya `No Auditing`. Setelah aktif, rule bawaan Wazuh `60228` langsung menangkap dengan level 4.
- **Sysmon event 1** proses `schtasks.exe`. Ini sumber yang lebih kaya (parent process + command line utuh berisi payload `/tr`), tapi secara default gak jadi alert karena `61603` level 0. Gap ini ditutup dengan custom rule `100605`.

Pelajaran teknis terbesarnya ada di format nilai field eventchannel: tanda kutip disimpan sebagai `\"`, jadi regex yang ngarep kutip polos gagal diam-diam. Aturan praktisnya, jangan asumsikan karakter persis di sekitar nilai yang dikutip, dan tes regex terhadap nilai field hasil decode, bukan terhadap command yang diketik.

Keterbatasan Sysmon 4.0 di Win7 tetap berlaku di sini: gak ada event 11 (file task di `C:\Windows\System32\Tasks\`) dan event 12–14 (registry `TaskCache`). Jadi deteksi pembuatan task bersandar ke command line `schtasks.exe` dan Security 4698.
