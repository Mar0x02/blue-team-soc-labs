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
<rule id="100605" level="10">
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

### E. Custom correlation rule 100604 — gabungin event 1 dan 4698 jadi satu alert

Setelah `100605` dipasang, satu kali pembuatan task ninggalin **dua alert terpisah** di Dashboard: `100605` (level 10) buat Sysmon event 1, dan `60228` (level 4) buat Security 4698. Analis harus nyambungin sendiri bahwa dua baris itu kejadian yang sama.

Masalahnya bukan cuma capek. `60228` level 4 itu rendah — di dashboard yang rame dia gampang tenggelam, padahal dia justru **bukti bahwa task-nya beneran terdaftar**, bukan sekadar `schtasks.exe` dipanggil. Rule `100604` naikin 4698 jadi level 12, tapi **cuma kalau** sebelumnya ada event 1 `schtasks.exe` yang mencurigakan.

```xml
<rule id="100604" level="12" timeframe="60">
    <if_sid>60228</if_sid>
    <if_matched_sid>100605</if_matched_sid>
    <description>Scheduled task creation confirmed: schtasks.exe spawned a PowerShell task (Sysmon 1) followed by Security 4698 task registration</description>
    <mitre>
        <id>T1053.005</id>
    </mitre>
    <group>scheduled_task,persistence,notify_discord,</group>
</rule>
```

Group `notify_discord` di baris terakhir itu tag routing, bukan bagian dari logic deteksi — dijelasin di [section F](#f-jalur-notifikasi--dari-rule-ke-discord-lewat-api--n8n).

| Opsi | Fungsi |
|------|--------|
| `if_sid` `60228` | Rule ini turunan rule bawaan 4698. Artinya yang **men-trigger** rule adalah event 4698, dan level 12-nya nimpa level 4 bawaan |
| `if_matched_sid` `100605` | Syaratnya: dalam timeframe sebelumnya udah ada alert `100605` (Sysmon event 1 `schtasks.exe`) |
| `timeframe` `60` | Jendela korelasi 60 detik |

Arah korelasinya penting buat dibaca bener: rule ini **fire di event terakhir**, bukan di event pertama. Event 1 yang duluan masuk (`100605`) tetap jadi alert-nya sendiri; 4698 yang datang belakangan yang naik jadi `100604`.

**Kenapa gak pakai `same_field`.** Di rule korelasi `100602` (lab T1059.001), dua event diikat pakai `same_field win.eventdata.ProcessGuid` — aman karena event 1 dan event 3 sama-sama event Sysmon, jadi punya field dengan nama yang sama. Di sini gak bisa, karena dua event-nya dari **sumber yang beda cara mandangnya**:

- **Sysmon event 1** itu *process-centric*. Yang dicatat proses `schtasks.exe`: `image`, `parentImage`, `commandLine`, `processGuid`, `user` (`LAB\Administrator`).
- **Security 4698** itu *object-centric*. Yang dicatat task yang terdaftar: `taskName`, `subjectUserName` (`Administrator`) + `subjectDomainName` (`LAB`), plus isi XML task-nya.

Gak ada satu pun field yang **nama dan nilainya** sama. User yang sama pun kesimpen dengan nama field beda dan format beda (`LAB\Administrator` vs dua field terpisah). Yang paling deket jadi jembatan adalah nama task, tapi di event 1 dia kekubur di dalam string `commandLine` (`/tn WindowsUpdateCheck`) sementara di 4698 dia field tersendiri. `same_field` cuma bisa bandingin field bernama sama apa adanya — dia gak bisa ngambil substring dari satu field buat dicocokin ke field lain.

Draft pertama rule ini sempat pakai `same_field win.eventdata.system.computer` dan `same_field win.eventdata.user`. Dua-duanya salah: path yang bener buat nama komputer adalah `win.system.computer` (bukan di bawah `eventdata`), dan `win.eventdata.user` emang gak ada di event 4698. Karena field yang gak ketemu bikin `same_field` gagal — konsisten sama temuan di `100602` — rule itu gak akan pernah fire. Akhirnya `same_field` dibuang sepenuhnya.

**Batasan yang harus disadari.** Tanpa `same_field`, ikatan dua event ini **cuma waktu**. Konsekuensinya:

- Kalau dalam satu jendela timeframe ada dua pembuatan task berbeda, `100604` gak bisa bedain 4698 yang mana pasangannya event 1 yang mana. Di lab ini gak masalah; di lingkungan nyata ini sumber ambiguitas — dan makin lebar timeframe-nya, makin besar peluangnya.
- `timeframe` awalnya diisi 5 detik dari observasi run `00:02` (jarak masuk Manager ~1 detik), terus dilebarin jadi 60. Alasannya: angka itu ngukur waktu **sampai di Manager**, bukan waktu kejadian. Sysmon dan Security itu dua channel terpisah dengan antrian sendiri di agent, jadi kalau agent lagi buffering, jendela yang sempit bisa kelewat dan korelasi diam-diam gak fire.
- Kalau urutannya kebalik — 4698 sampai di Manager duluan sebelum `100605` fire — korelasi juga gak jalan, karena `if_matched_sid` nyari alert yang **udah** ada di memori.
- Di lab ini cuma `WIN7-VICTIM` yang kirim Sysmon + Security, jadi gak ada risiko nyocokin lintas host. Kalau nanti ada agent Windows kedua, perlu dicek apakah `if_matched_sid` otomatis nge-scope per-agent atau bisa nyambungin event 1 dari host A dengan 4698 dari host B. Ini **belum diuji**.

Pengikatan yang beneran per-task (normalisasi `/tn` dari `commandLine` terus dicocokin ke `taskName` setelah backslash depannya di-strip) gak bisa dikerjain di layer rule Wazuh. Itu ranah layer korelasi di atasnya, yang bebas nulis logic normalisasi sendiri.

**Hasil live — `100604` fire.** Skenario Step 4 dijalanin ulang tanggal 22 September 2026:

| Time (Dashboard) | Rule | Detail |
|------------------|------|--------|
| 2026-09-22 17:27:52.061 | `100605` | `C:\Windows\System32\schtasks.exe`, GUID `{AF48A474-5814-6AB2-0000-00104E021200}` |
| 2026-09-22 17:27:52.062 | `100604` | Korelasi — field `win.eventdata.image` kosong, wajar karena event pemicunya 4698, bukan Sysmon event 1 |

Jaraknya **1 milidetik**. Dua channel yang tadinya dikhawatirkan punya antrian sendiri ternyata nyampe Manager praktis barengan, jadi lebar `timeframe` gak jadi faktor di kondisi ini — 5 detik maupun 60 detik sama-sama lolos. Yang perlu diinget, ini hasil satu run di host yang lagi senggang; angka itu bukan jaminan buat agent yang lagi sibuk.
### F. Jalur notifikasi — dari rule ke Discord lewat API + n8n

Rule `100604` cuma nyelesaiin separuh masalah. Dia bikin konfirmasi "task beneran terdaftar" jadi alert level 12 di Wazuh, tapi analis masih harus buka Dashboard buat liat. Di project ini udah ada layer orkestrasi n8n yang dibangun di lab [`soc-automation`](../../../../soc-automation/), dan lab ini nyambung ke situ lewat **tiga jalur yang beda sifatnya**.

#### Jalur 1 — push per-alert (Fase 1)

Wazuh Integrator (`custom-n8n`) nembak tiap alert yang lolos threshold ke webhook n8n, terus n8n nge-fan-out ke Jira (ticket) dan Discord (notifikasi). Setup-nya di [`Infrastructure/n8n-alerting-pipeline-setup.md`](../../../../../Infrastructure/n8n-alerting-pipeline-setup.md).

Gate pertama ada di level rule, karena Integrator disaring `<level>7</level>`:

| Alert | Level | Masuk pipeline (≥7)? |
|-------|-------|----------------------|
| `100605` — Sysmon 1, `schtasks.exe` bikin task PowerShell | 10 | ✅ |
| `60228` — Security 4698 (bawaan Wazuh) | 4 | ❌ |
| `100604` — korelasi event 1 + 4698 | 12 | ✅ |

Baris tengah itu inti persoalannya. Tanpa `100604`, bukti paling penting di lab ini — **4698 yang mengonfirmasi task-nya terdaftar, bukan cuma `schtasks.exe` dipanggil** — gak akan pernah keluar dari Wazuh, karena level 4 ketahan threshold. Jadi level 12 di `100604` bukan sekadar bikin baris di Dashboard jadi merah; dia yang bikin event itu lolos ke pipeline. Ini juga alasan kenapa level rule mesti diputusin sambil ngeliat threshold Integrator, bukan dinilai sendirian.

#### Masalah gate kedua: gak semua yang masuk pipeline layak dinotif

Threshold `≥7` itu instrumen tumpul. Semua alert level 7 ke atas ikut ke Discord, termasuk `100605` yang sebenernya cuma *upaya* bikin task — belum tentu berhasil kedaftar. Kalau semua dikirim, Discord jadi berisik dan analis balik ke kondisi yang justru mau dihindari pipeline ini: alert fatigue.

Yang paling layak dinotif justru kelas sinyal yang spesifik: **korelasi lintas decoder**. Alert `100604` naik dari dua sumber yang jalannya sendiri-sendiri — Sysmon (event 1, lewat decoder Sysmon) dan Security 4698 (lewat decoder eventchannel Windows). Dua sumber independen yang saling mengonfirmasi itu jauh lebih kecil kemungkinan false positive-nya ketimbang alert satu sumber. Itu sifat yang pantes dapet notifikasi real-time.

Penandanya ditempel sebagai **group tambahan di rule deteksi**:

```xml
<group>scheduled_task,persistence,notify_discord,</group>
```

`scheduled_task` dan `persistence` ngejawab "ini serangan apa", `notify_discord` ngejawab "ini dikirim ke mana". Dua pertanyaan beda numpang di satu rule — dan bagian berikutnya ngejelasin kenapa akhirnya begitu, padahal desain awalnya bukan itu.

#### Percobaan yang gagal: misahin routing jadi rule sendiri

Ide awalnya, keputusan notifikasi gak ditempel ke rule deteksi, tapi dikasih rule sendiri (`100606`) yang tugasnya khusus nandain korelasi cross-decoder sebagai sinyal yang layak dinotif. Alasannya masuk akal di atas kertas: rule deteksi tetap bersih, dan routing bisa diubah tanpa nyentuh rule yang udah divalidasi. Dua percobaan dilakuin, dua-duanya ngajarin hal yang beda.

**Percobaan 1 — `<if_sid>60228</if_sid>`.** Rule notif ditempel langsung ke event 4698, sejajar dengan `100604`. Hasilnya `100606` **gak pernah fire**; yang muncul di Dashboard cuma `100605` dan `100604`. Sebabnya, `100604` dan `100606` jadi dua rule **bersaudara** di bawah induk yang sama, dan cuma satu yang bisa menang per event — `100604` yang ditulis duluan di file yang dapet. Di luar itu, rule ini juga salah secara logika: tanpa syarat korelasi, dia bakal match **tiap 4698 apa pun**, termasuk task bikinan Windows Update atau installer.

**Percobaan 2 — `<if_sid>100604</if_sid>`.** Rule notif dijadiin anak dari rule korelasi. Hasilnya `100606` fire — tapi `100604` **ilang** dari Dashboard, digantiin `100606`.

Dua percobaan itu nutup satu pertanyaan yang sebelumnya cuma asumsi, dan ngebuka satu batasan yang gak bisa dilangkahi:

- **`if_sid` bisa nunjuk ke rule korelasi.** Rule yang fire lewat `if_matched_sid` tetap ditelusuri anaknya sama analysisd. Ini sempat diragukan waktu desain, dan sekarang kejawab: bisa.
- **Satu event cuma ngehasilin satu alert.** Analysisd nyari rule yang match paling dalam, ketemu, berhenti. Rule anak **nggantiin** alert induknya, bukan nambahin di sebelahnya.

Poin kedua itu yang mematikan desainnya. Selama rule notif nempel sebagai anak, dia selalu menang dan alert korelasinya lenyap. Alert yang muncul jadi ber-ID `100606` padahal logic korelasinya ada di `100604` — tiap kali baca alert, harus loncat satu rule buat ngerti kenapa dia fire.

#### Kenapa "rule silent khusus integrasi" juga gak bisa

Jalan keluar yang keliatan menarik: bikin `100606` gak nge-alert (level 0), biar `100604` tetap tampil di Dashboard sementara `100606` cukup jadi penanda buat n8n. Ini gak jalan, karena dua sebab yang numpuk.

Pertama, `wazuh-integratord` itu konsumen `alerts.json` — dia tailing file itu, nyaring pakai `<level>`/`<rule_id>`/`<group>`, terus manggil script integrasi. Rule yang gak nulis alert gak akan pernah keliatan sama dia. Ini berlaku buat **semua jalur keluar yang sifatnya push** di Manager:

| Jalur | Sumber | Sifat |
|-------|--------|-------|
| `integratord` (n8n) | `alerts.json` | push |
| Active Response | alert | push |
| `csyslogd` (syslog output) | alert | push |
| Email alert | alert | push |
| Archives (`archives.json` → `wazuh-archives-*`) | semua event, termasuk yang gak jadi alert | pull |

Cuma baris terakhir yang bisa ngeliat event non-alert, dan itu pun harus di-*pull* dari Indexer, bukan dikirim. (Terbuka buat lab ini, karena archives udah dikirim ke Indexer — lihat Part 4 di [`wazuh-setup.md`](../../../../../Infrastructure/wazuh-setup.md). Apakah entry archives ikut bawa metadata `rule.id`/`rule.groups` buat match level 0, belum dicek.)

Kedua, dan ini yang lebih menentukan: aturan satu-event-satu-alert tetap berlaku buat rule level 0. Kalau `100606` dibikin level 0 sebagai anak `100604`, dia tetap yang menang — bedanya sekarang gak ada alert yang ditulis sama sekali, jadi `100604` ilang dari `alerts.json`. Bukan cuma notifikasinya yang mati, alert korelasinya ikut hilang.

Kesimpulannya: **di Wazuh, keputusan routing gak bisa berdiri sebagai rule terpisah.** Yang tersisa ya group tag di rule deteksi — satu kata, dan pemisahan sesungguhnya terjadi di layer konsumen (n8n).

#### Di mana tag itu dievaluasi

Blok `<integration>` sendiri bisa disaring pakai `<group>` (selain `<level>`, `<rule_id>`, `<event_location>`). Tapi di arsitektur project ini, **filter group gak dipasang di Integrator**, karena itu bakal ngerusak Fase 1 dan Fase 2:

- Kalau `<level>7</level>` diganti `<group>notify_discord</group>`, Integrator berhenti ngirim alert lain ke n8n — artinya **ticket Jira per-alert berhenti kebikin**. Padahal Jira Fase 1 itu system of record-nya, bukan sekadar notifikasi.
- Fase 2 nyari ticket-ticket Fase 1 lewat JQL `alert_id` buat di-link ke ticket Incident. Kalau ticket-nya gak pernah ada, issue link-nya nunjuk ke kosong. Korelasinya sendiri tetap aman — `correlation_logic.py` baca alert langsung dari Indexer (`wazuh-alerts-*`), gak lewat Integrator — jadi yang rusak cuma jejak ticketing-nya, dan itu rusak diam-diam.

Jadi pembagiannya: **`<level>7</level>` tetap jadi gate masuk pipeline (→ Jira), group `notify_discord` jadi gate ke Discord**, dievaluasi di node IF n8n sebelum cabang Discord — ngecek `rule.groups` alert ngandung `notify_discord`.

Opsi lain yang dipertimbangkan tapi gak dipilih: bikin blok `<integration>` kedua khusus `<group>notify_discord</group>` yang nembak webhook n8n terpisah. Itu memang naruh filternya di Integrator (lebih deklaratif), tapi harganya dua jalur push paralel + workflow kedua yang harus dijaga sinkron, buat hasil yang sama.

Hasil akhirnya tiga tingkat, tiap tingkat punya pertanyaan sendiri:

| Tujuan | Isi | Ditentukan oleh |
|--------|-----|-----------------|
| Wazuh Dashboard | Semua alert (`100605`, `60228`, `100604`) | Rule fire — riwayat lengkap buat investigasi |
| Jira | Alert level ≥7 (`100605`, `100604`) | `<level>` di blok `<integration>` |
| Discord | Alert ber-group `notify_discord` (`100604`) | `<group>` di rule + node IF n8n |

#### Jalur 2 — pull per-incident (Fase 2)

n8n Schedule Trigger manggil `POST /correlate/tick` tiap N menit, service-nya nge-cluster alert jadi incident, bikin narasi AI + RAG, terus ngirim satu notifikasi Discord per incident (bukan per alert) plus ticket Jira yang di-link ke ticket Fase 1 anggotanya. Setup-nya di [`Infrastructure/n8n-correlation-workflow-setup.md`](../../../../../Infrastructure/n8n-correlation-workflow-setup.md).

Jalur ini yang awalnya direncanain buat nutup batasan yang kesisa dari `100604`. Pengikatan per-task yang gak bisa dikerjain `same_field` — ekstrak nama task dari `/tn` di `commandLine` event 1, strip backslash depan dari `taskName` 4698, baru dicocokin — di layer API bebas ditulis sebagai logic normalisasi biasa. Jadi pembagian kerjanya: **Wazuh ngangkat sinyal & ngiket kasar pakai timeframe, layer API yang ngiket presisi per-task.**

Yang gak kepikiran waktu itu: jalur 2 jalan per tick, jadi notifikasinya nunggu jadwal berikutnya. Buat konfirmasi persistence yang udah level 12, itu kelamaan. Pengikatan per-task akhirnya ditaruh di jalur ketiga yang sifatnya push.

Bedanya buat analis juga nyata. Jalur 1 ngasih notifikasi mentah ("ada alert level 12 di WIN7-VICTIM"), jalur 2 ngasih satu notifikasi yang udah nyeritain rangkaiannya. Buat teknik persistence kayak T1053.005 yang jarang berdiri sendiri — biasanya nyambung ke execution sebelumnya (lab [T1059.001](<../../Execution/Command and Scripting Interpreter (T1059.001 - PowerShell)/README.md>)) — jalur 2 yang lebih ngasih konteks.

#### Jalur 3 — push per-alert dengan pengikatan per-task

Route `POST /notify/cross-decoder` di [`AI-Rag-Integration/api-service.py`](../../../../../AI-Rag-Integration/api-service.py), dipanggil node n8n dari cabang webhook yang sama kayak Jalur 1 — jadi gak nambah jalur push dari Manager, cuma nambah cabang di n8n.

Masalah yang dia selesaikan: alert `100604` dipicu event 4698, jadi dia **gak bawa field Sysmon sama sekali**. Command line yang isinya payload task — bagian paling berguna buat analis — cuma ada di alert `100605`, yang datang sebagai alert terpisah. Route ini yang nyatuin: alert yang nyampe duluan disimpen di SQLite, yang nyampe belakangan narik pasangannya lewat kunci nama task yang udah dinormalisasi (`\WindowsUpdateCheck` → `windowsupdatecheck`), terus ngerakit satu pesan Discord.

Hasil live, run 24 September 2026 04:49:41 UTC:

```
🚨 Scheduled task creation confirmed: schtasks.exe spawned a PowerShell task
   (Sysmon 1) followed by Security 4698 task registration
Host: WIN7-VICTIM | Rule: 100604 (level 12)
Task: WindowsUpdateCheck
Waktu: 2026-09-24T04:49:41.210+0000

Dari alert eksekusi 100605 (2026-09-24T04:49:41.206+0000):
Parent: C:\Windows\System32\cmd.exe
User: LAB\Administrator
Command: schtasks /create /tn "WindowsUpdateCheck" /tr "powershell.exe -NoProfile
         -WindowStyle Hidden -Command \"Write-Host 'Persistence task executed -
         Lab Test'\"" /sc onlogon /ru SYSTEM /f
```

Empat baris terakhir itu yang gak mungkin ada kalau notifikasinya cuma ngandelin alert `100604`. Analis L1 dapet jawaban "task apa, jalanin apa, dibikin siapa" tanpa buka Dashboard.

Bukti di channel Discord `#correlation-lab-spesifc`. Ada dua run yang sama-sama berhasil dipasangin: `04:49:41` UTC (yang di atas) dan `08:07:47` UTC. Di dua-duanya, alert korelasi `100604` bawa command line dari alert eksekusi `100605`, dan selisih timestamp kedua alert cuma 1–4 milidetik.

![Notifikasi Discord hasil pairing 100604 + 100605 lewat route /notify/cross-decoder](<./assets/discord notif alert correlation log.png>)

#### Gate yang gak keliatan: level rule di repo vs di Dell

Percobaan pertama jalur 3 keliatan jalan — notifikasi Discord masuk — tapi isinya selalu:

> ⚠️ Alert eksekusi pasangannya gak ketemu dalam 300 detik terakhir.

Dan di history n8n, **gak ada eksekusi sama sekali buat event ID 1**. Query langsung ke Indexer Dell (`wazuh-alerts-*`) yang ngejawab:

| Waktu (UTC) | Rule | Level | Event |
|-------------|------|-------|-------|
| 04:29:11.275 | `100605` | **6** | Sysmon 1 |
| 04:29:11.289 | `100604` | 12 | 4698 |

File rule di repo udah `level="10"`, tapi ruleset yang jalan di Dell masih versi sebelum level itu dinaikin. Integrator disaring `<level>7</level>`, jadi `6 < 7` bikin alert eksekusi **gak pernah di-forward ke n8n** — tabel pending gak pernah keisi, dan pasangannya mustahil ketemu.

Yang perlu dicatat: **deteksinya sendiri gak rusak sedikit pun.** `100604` tetap fire normal, karena `if_matched_sid` gak peduli level rule anaknya. Yang mati cuma jalur notifikasi, dan matinya sebagian — notif tetap dikirim, cuma konteksnya kosong. Ini bentuk konkret dari apa yang udah ditulis di awal section ini: **level rule itu gate ke pipeline, bukan cuma warna di Dashboard.** Bedanya, di sini gate-nya nutup gara-gara file rule di repo dan di Dell beda versi — kelas masalah yang gak bakal ketangkep `wazuh-logtest`, karena logic rule-nya emang bener.

Pelajaran operasionalnya: kalau notifikasi keliatan aneh tapi rule-nya "udah bener di repo", yang pertama dicek bukan logic rule-nya, tapi **apakah yang jalan di Manager emang versi itu** — lewat level yang kebawa di alert, bukan lewat isi file.

#### Race condition: dua alert, dua eksekusi n8n, 4 milidetik

Setelah ruleset disinkronin dan pairing-nya berhasil, ketahuan desain route-nya masih rapuh. Versi pertama nentuin peran dari rule ID: `100605` **selalu** nyimpen, `100604` **selalu** narik. Itu asumsi bahwa alert eksekusi selalu nyampe duluan.

Asumsi itu gak dijamin. Dua alert ini lahir dari event yang beda, di-forward Integrator sebagai dua panggilan webhook terpisah, dan diproses n8n sebagai **dua eksekusi paralel** yang masing-masing ketahan panggilan Ollama puluhan detik di cabang AI triage. Jaraknya sendiri cuma **4 milidetik** (run 04:49:41), dan pernah **1 milidetik** (run 22 September). Pada jarak segitu, urutan datengnya ditentukan antrian Ollama dan latency Jira — bukan urutan kejadian di Win7.

Kalau urutannya kebalik, yang ada cuma retry 3× dengan jeda 0,5 detik: **1 detik grace**, lawan cabang yang bisa ketahan puluhan detik. Lewat itu, notifikasinya kirim "pasangannya gak ketemu" padahal pasangannya lagi di jalan.

Ada efek samping yang lebih jahat dari sekadar notif tanpa konteks. Row `100605` yang datang telat tetap disimpen, gak ada yang konsumsi, dan nongkrong 30 menit. Run lab berikutnya dalam jendela 300 detik bisa **nyomot row basi dari run sebelumnya** — notifikasinya keliatan sukses, command line-nya dari run yang salah.

Perbaikannya: **peran gak ditentukan dari rule ID, tapi dari siapa yang nyampe belakangan.** Sisi mana pun yang duluan bakal nyimpen dan diem; yang belakangan yang masangin dan ngirim notifikasi. Urutan jadi gak relevan.

Tiga hal yang muncul justru dari perbaikan itu, dan ketiganya baru ketahuan pas ditulisin tes:

- **Kalau dua-duanya nyampe benar-benar barengan, notifikasinya bisa ilang total.** Cari-lalu-simpen itu *read-modify-write*. Tanpa lock, dua alert sama-sama gak nemu pasangan, sama-sama nyimpen, dan gak ada yang ngirim apa-apa — gagal yang lebih berbahaya dari race aslinya, karena gak ninggalin jejak. Dibungkus `BEGIN IMMEDIATE` + `PRAGMA busy_timeout`.
- **Pesan "pasangannya gak ketemu" jadi gak pernah muncul.** Dengan pengikatan simetris, alert korelasi yang pasangannya gak pernah datang cuma diem di tabel — padahal justru pesan itu yang bikin bug level-6 di atas ketahuan. Dikembalikan lewat endpoint terpisah `POST /notify/cross-decoder/sweep`, karena batas "nyerah nunggu" itu soal lewatnya waktu, bukan soal ada alert baru masuk.
- **Umur row diukur dari timestamp alert, bukan dari kapan row-nya disimpen.** Alert yang datang dengan timestamp lebih tua dari retention kehapus di request yang sama pas dia baru masuk. Di lab dua angka itu selisihnya milidetik jadi gak pernah keliatan, tapi agent Wazuh yang abis reconnect nge-flush antrian log-nya sekaligus dengan timestamp jam-jam sebelumnya. Dipisah jadi dua kolom: **`timestamp` alert buat nentuin pasangan, wall clock buat nentuin kapan nyerah nunggu.**

Pola yang keulang di tiga-tiganya: perbaikan race gak selesai pas urutannya diberesin. Yang kegeser justru *bentuk* gagalnya — dari "notif kurang konteks" (keliatan) jadi "gak ada notif sama sekali" (sunyi). Buat pipeline deteksi, gagal yang sunyi itu yang lebih mahal.

#### Status

| Komponen | Status |
|----------|--------|
| Wazuh Integrator (`custom-n8n`) di Dell | ✅ Jalan — alert Win7 asli ngalir ke n8n |
| Rule `100605` + `100604` fire di alert asli | ✅ Confirmed (section E) |
| Sinkronisasi ruleset repo → Dell | ✅ Dibenerin 24 Sep 2026, `100605` sekarang level 10 |
| Jalur 3 — pairing per-task + notif Discord | ✅ Live, dengan command line lengkap |
| Pengikatan simetris (fix race condition) | ⚠️ Lolos 9 skenario tes sintetis, **belum diuji pakai run schtasks asli** |
| Endpoint `/notify/cross-decoder/sweep` | ⚠️ Udah ada, **belum di-wire** ke Schedule Trigger n8n |
| Node IF filter group `notify_discord` | ❌ Belum dibikin — semua alert level ≥7 masih ikut ke Discord |

Yang masih kebuka dan belum kejawab:

- Run 04:45:49 nunjukin `100605` dan `60228` (4698 polos, level 4) fire di timestamp yang sama persis, tapi **`100604` gak fire sama sekali**. Dugaannya 4698 diproses analysisd sebelum `100605` selesai match, jadi `if_matched_sid` belum keisi. Ini batasan "urutan kebalik" yang udah ditulis di section E — sekarang ada buktinya. Gagalnya sunyi: level 4, di bawah threshold Integrator, jadi gak ada notif apa pun. Ini di layer analysisd, di luar jangkauan route API.
- Pencocokan group di Wazuh belum dites apakah exact-match per-elemen atau substring. Kalau substring, nama group yang jadi prefix nama lain (misal nanti ada `notify_discord_low`) bakal ikut ke-match. Sementara ini nama `notify_discord` dijaga gak jadi prefix group lain.
- Tag operasional nongol di `rule.groups` alert, campur sama group deteksi kayak `scheduled_task`. Efek sampingnya positif (bisa difilter di Dashboard), tapi sadar aja bahwa keputusan routing sekarang kelihatan di data alert.

### G. Custom rule 100606 — task beneran jalan (fase eksekusi payload)

Section C sampai F semuanya soal **pembuatan** task. `100605` nangkep `schtasks.exe` dipanggil, `100604` ngonfirmasi task-nya kedaftar. Tapi dua-duanya gak ngejawab pertanyaan berikutnya: **payload-nya beneran jalan atau nggak?** Task `/sc onlogon` bisa aja nongkrong berhari-hari sebelum ada yang logon, dan saat itu `schtasks.exe` udah lama selesai.

Pas task jalan, Task Scheduler di Win7 nge-spawn **`taskeng.exe`**, dan `taskeng.exe` yang nge-spawn action task-nya. Jadi yang dicari adalah Sysmon event 1 dengan `image` `powershell.exe` dan `parentImage` `taskeng.exe`.

```xml
<rule id="100606" level="12">
    <if_sid>61603</if_sid>
    <field name="win.system.eventID" type="pcre2">1</field>
    <field name="win.eventdata.image" type="pcre2">(?i)\\powershell\.exe$</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)-NoProfile|-nop</field>
    <field name="win.eventdata.parentImage" type="pcre2">(?i)(?:taskeng|svchost)\.exe$</field>
    <description>Sysmon: PowerShell execution triggered by Scheduled Task Engine (persistence re-execution)</description>
    <mitre>
        <id>T1053.005</id>
        <id>T1059.001</id>
    </mitre>
    <group>persistence,scheduled_task,</group>
</rule>
```

| Field | Fungsi |
|-------|--------|
| `image` `\\powershell\.exe$` | Proses yang jalan adalah PowerShell |
| `commandLine` `-NoProfile\|-nop` | Flag yang dipakai payload task di Step 4, termasuk bentuk singkatannya (lihat backlog bypass flag di lab T1059) |
| `parentImage` `(taskeng\|svchost)\.exe$` | `taskeng.exe` itu host eksekusi task di Win7. `svchost.exe` buat nutup Windows versi baru, yang jalanin task lewat service `Schedule` |
| `mitre` T1053.005 + T1059.001 | Satu kejadian nyentuh dua teknik: task-nya (persistence) dan PowerShell yang dijalanin (execution) |
| `group` `persistence,scheduled_task` | Satu keluarga sama `100604`/`100605`, jadi tiga fase task bisa difilter bareng di Dashboard |

Buat mancing eksekusinya tanpa harus logout, task-nya dipicu manual:

```cmd
schtasks /run /tn "WindowsUpdateCheck"
```

#### Debugging: rule yang gak mau fire

Rule ini dibikin 24 September 2026, dan **seharian gak fire sekali pun**. Padahal event pemicunya jelas nyampe Manager: kelihatan di `wazuh-archives-*` dengan `rule: None`, decoder `windows_eventchannel`, parent `taskeng.exe`, user `NT AUTHORITY\SYSTEM`.

Rule-nya dipreteli sampai paling telanjang, cuma `if_sid 61603` + satu field `parentImage (?i)taskeng`. Tetap gak fire. Varian yang gantung ke `<if_group>sysmon_event1</if_group>` (jalur yang dipakai rule bawaan) juga gak fire. Hipotesis yang diuji satu-satu, dan semuanya gugur:

| # | Hipotesis | Cara ngujinya | Hasil |
|---|-----------|---------------|-------|
| 1 | Rule belum ke-deploy ke Dell | `grep` di `etc/rules/` | Ada, cuma satu definisi |
| 2 | ID `100606` dobel (ID ini sempat dipakai rule routing yang udah dihapus, lihat section F) | `grep -rn 'id="100606"'` ke `ruleset/rules/` + `etc/rules/` | Cuma satu |
| 3 | Manager belum restart setelah edit | Bandingin **`ctime`** file dengan waktu restart dan waktu event | Urutannya bener: edit → restart → event |
| 4 | Ruleset gagal di-parse | `wazuh-analysisd -t` + `ossec.log` | Exit 0, gak ada error |
| 5 | `sysmon_rules.xml` gak ke-load | Rule lain di file yang sama (`100601`) | `100601` fire normal |
| 6 | Rule bawaan level 0 nyerobot (kayak `92101` di lab T1059) | Cek 4 rule level 0 di `0800-sysmon_id_1.xml` | Gak ada yang match event ini |
| 7 | Parent/user/session yang bikin beda | Jalanin payload yang sama dari `cmd.exe` sebagai Administrator | Tetap gak fire |
| 8 | Pipeline alert WIN7 mati | Alert lain dari WIN7 (`60608`) | Ngalir normal |
| 9 | Decoder beda | Bandingin event yang jalan dan yang nggak | Dua-duanya `windows_eventchannel` / `EventChannel` |

Di sepanjang proses itu ketemu tiga jebakan alat, yang masing-masing sempat bikin kesimpulan salah:

- **`mtime` nipu.** `mv`, `scp -p`, dan `cp -p` bawa `mtime` dari file sumber, jadi file yang baru nyampe bisa keliatan lebih tua dari waktu restart. Buat mutusin "restart udah sesudah edit apa belum", yang dipakai **`ctime`** (`stat -c %z`).
- **`wazuh-logtest` gak bisa dipakai buat rule Sysmon/eventchannel.** Input dari stdin selalu kepilih decoder `json` generik, sementara pohon rule Sysmon gantung di `61600` yang mensyaratkan `<decoded_as>windows_eventchannel</decoded_as>`. Phase 3 gak pernah muncul, dan `-l "EventChannel"` gak ngubah apa-apa. Artinya **semua rule Win7 di project ini cuma bisa divalidasi lewat event asli dari agent**.
- **`wazuh-analysisd -t` cuma nge-parse file di disk.** Exit 0 artinya file-nya valid, bukan bukti bahwa isi memori analysisd yang lagi jalan sama dengan file itu.

Langkah terakhir yang disiapin, `analysisd.debug=2` buat ngeliat rule mana yang dicoba analysisd dan berhenti di mana, gak sempat dijalanin.

#### Hasil — pagi berikutnya, dia fire

25 September pagi, rule di Dell dibalikin ke versi lengkap di atas (versi repo, bukan versi telanjang buat debugging), dan skenarionya dijalanin ulang. **`100606` fire**, dua kali:

| Time (Dashboard) | Rule | Event | `image` | `parentImage` |
|------------------|------|-------|---------|---------------|
| 2026-09-25 10:34:59.095 | `100606` | 1 | `...\WindowsPowerShell\v1.0\powershell.exe` | `C:\Windows\System32\taskeng.exe` |
| 2026-09-25 10:47:22.959 | `100606` | 1 | `...\WindowsPowerShell\v1.0\powershell.exe` | `C:\Windows\System32\taskeng.exe` |

![Alert 100606 di wazuh-alerts-*, parent taskeng.exe](<./assets/alert 100606 taskeng.png>)

Di `wazuh-archives-*`, run `10:47:22` kelihatan rantai lengkapnya, semua dalam ~60 milidetik (event 9 yang nyelip di antaranya gak ditulis di tabel):

| Time | Event | Proses | Catatan |
|------|-------|--------|---------|
| 10:47:22.914 | 9 | `schtasks.exe` | Nongol 1 ms sebelum `taskeng.exe`, konsisten sama `schtasks /run` |
| 10:47:22.915 | 1 | `taskeng.exe` | Command line `taskeng.exe {CF6E4F5E-...} S-1-5-18:NT AUTHORITY\System:Service:` |
| 10:47:22.959 | 1 | `powershell.exe` | `powershell.exe -NoProfile -WindowStyle Hidden -Command \"Write-Host \"Persistence task executed - Lab Test\"\"` → jadi `100606` |
| 10:47:22.974 | 1 | `conhost.exe` | Console host buat PowerShell |

![Rantai eksekusi task di wazuh-archives-*: schtasks → taskeng → powershell → conhost](<./assets/archives task execution chain.png>)

> **Catatan evidence:** dua alert di atas fire waktu description rule masih `Sysmon: Command line execution of powershell.exe with -NoProfile flags detected` dengan group `command_injection,command_scripting`. Setelah itu yang diubah cuma description, group, dan MITRE ID, logic match-nya tetap sama.

**Root cause kenapa kemarin gak fire: gak ketemu.** Beda yang kelihatan cuma dua: versi rule (telanjang vs lengkap) dan waktunya (sore kemarin vs pagi ini). Hipotesis 1–9 di atas udah nyingkirin penyebab yang biasanya, jadi hasil ini dicatat apa adanya: **rule yang sama sekarang fire di event asli, dan itu yang jadi bukti deteksinya.**

Pelajaran yang tetap kepake walau root cause-nya gak ketemu: buat rule Win7, satu-satunya bukti yang bisa dipegang adalah **alert di `wazuh-alerts-*` dari event asli**. `logtest` gak bisa, `analysisd -t` cuma ngecek sintaks, dan timestamp file bisa nipu.

#### Batasan

- **Nama task gak kebawa.** Command line `taskeng.exe` cuma berisi GUID dan SID, gak ada nama task. Jadi `100606` gak bisa langsung dipasangin ke alert pembuatan (`100604`/`100605`) lewat nama task kayak di jalur 3. Yang bisa dipakai ikatan cuma host + waktu.
- **Bergantung ke flag `-NoProfile`.** Payload task yang jalanin PowerShell tanpa flag itu (atau yang jalanin `cmd.exe`, `wscript.exe`, binary lain) gak ketangkep.
- **`svchost.exe` di `parentImage` itu lebar.** Di Win7 cabang itu gak kepake (task jalan lewat `taskeng.exe`), tapi `svchost.exe` induk dari banyak service, jadi di host yang lebih baru rule ini bisa match PowerShell yang bukan dari task.
- Level 12 berarti alert ini lolos threshold Integrator (≥7) dan ikut ke n8n. Tapi dia **gak punya** group `notify_discord` dan gak diproses route `/notify/cross-decoder`, jadi belum ada notif Discord khusus buat fase eksekusi.

---

## Kesimpulan

Pembuatan scheduled task sebagai mekanisme persistence di Win7 **bisa dideteksi dari dua sumber**:

- **Security 4698**. Butuh audit policy `Other Object Access Events` diaktifkan dulu, karena default-nya `No Auditing`. Setelah aktif, rule bawaan Wazuh `60228` langsung menangkap dengan level 4.
- **Sysmon event 1** proses `schtasks.exe`. Ini sumber yang lebih kaya (parent process + command line utuh berisi payload `/tr`), tapi secara default gak jadi alert karena `61603` level 0. Gap ini ditutup dengan custom rule `100605`.

Dua sumber itu dipasangin lewat rule korelasi `100604`: 4698 naik ke level 12 kalau sebelumnya ada event 1 `schtasks.exe` yang mencurigakan. Bedanya dengan korelasi `100602` di lab T1059.001, di sini dua event-nya gak bisa diikat pakai `same_field` — Sysmon mandang kejadian ini sebagai *proses*, Security 4698 mandangnya sebagai *object task*, jadi gak ada field yang nama sekaligus nilainya sama. Ikatannya cuma timeframe — dan itu cukup buat lab ini: run 22 September 2026 nunjukin `100605` dan `100604` fire beruntun dalam jarak 1 milidetik.

Level `100604` juga nentuin apakah temuan ini nyampe ke analis di luar Dashboard: Wazuh Integrator ke n8n disaring level ≥7, jadi `60228` level 4 ketahan sementara `100604` level 12 lolos masuk pipeline. Dari situ, yang nentuin dia dinotif ke Discord atau cuma jadi ticket Jira adalah group `notify_discord` di rule-nya. Sempat dicoba misahin keputusan itu jadi rule sendiri, tapi gagal karena Wazuh cuma ngasih satu alert per event — rule anak nggantiin induknya, bukan nambahin.

Jalur notifikasi itu sekarang **udah jalan end-to-end**: alert Win7 asli nyampe Discord lengkap dengan command line task-nya, lewat route pairing per-task di layer API. Dua hal yang ngeganjal di situ dua-duanya soal waktu, bukan soal logic deteksi. Pertama, ruleset di Dell ketinggalan dari repo, dan level `100605` yang masih 6 bikin alert eksekusi ketahan threshold Integrator — deteksinya tetap jalan sempurna, yang mati cuma konteks notifikasinya. Kedua, dua alert yang mau dipasangin nyampe cuma 4 milidetik terpaut lewat dua eksekusi n8n paralel, jadi urutan datengnya gak bisa diasumsikan; route-nya ditulis ulang supaya sisi mana pun yang nyampe belakangan yang masangin. Dari situ pelajaran yang paling kepake: tiap kali race-nya diberesin, yang kegeser itu *bentuk* gagalnya — dan bentuk yang paling mahal buat pipeline deteksi bukan notif yang kurang lengkap, tapi notif yang gak pernah dikirim sama sekali.

Fase **eksekusi** task ditutup `100606`: PowerShell `-NoProfile` yang di-spawn `taskeng.exe`. Rule ini seharian gak fire dengan sembilan hipotesis yang gugur semua, lalu fire di event asli pagi berikutnya tanpa root cause yang ketemu. Yang kebawa dari situ bukan jawabannya, tapi cara buktiinnya: buat rule Win7, `wazuh-logtest` gak bisa dipakai dan `wazuh-analysisd -t` cuma ngecek sintaks, jadi satu-satunya bukti yang sah adalah alert di `wazuh-alerts-*` dari event asli.

Pelajaran teknis terbesarnya ada di format nilai field eventchannel: tanda kutip disimpan sebagai `\"`, jadi regex yang ngarep kutip polos gagal diam-diam. Aturan praktisnya, jangan asumsikan karakter persis di sekitar nilai yang dikutip, dan tes regex terhadap nilai field hasil decode, bukan terhadap command yang diketik.

Keterbatasan Sysmon 4.0 di Win7 tetap berlaku di sini: gak ada event 11 (file task di `C:\Windows\System32\Tasks\`) dan event 12–14 (registry `TaskCache`). Jadi deteksi pembuatan task bersandar ke command line `schtasks.exe` dan Security 4698.
