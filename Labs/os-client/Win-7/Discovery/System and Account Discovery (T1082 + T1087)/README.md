# System and Account Discovery (T1082 + T1087) — Win7 Victim

## Tujuan

Simulasi **discovery** di Win7 victim (`10.10.20.10`, LAN2) sesuai MITRE ATT&CK **T1082 (System Information Discovery)**, **T1033 (System Owner/User Discovery)**, dan **T1087 (Account Discovery)**, lalu amati sinyal apa yang bisa ditangkap **Sysmon** di endpoint ini.

Ini lanjutan dari lab [T1053.005 Scheduled Task](<../../Persistence/Scheduled Task (T1053.005)/README.md>). Setelah attacker punya akses yang bertahan, langkah berikutnya biasanya ngenalin lingkungan: host ini apa, OS-nya versi berapa, user-nya siapa, dan privilege apa yang dia pegang.

Ini lab **assume-breach**. Titik berangkatnya adalah asumsi attacker udah bisa ngetik command di Win7 (disimulasikan dengan ngetik manual di `cmd.exe`). Skenarionya sengaja simpel: cuma command bawaan Windows yang biasa dipakai buat recon. Fokusnya **deteksi**: command yang satu per satu kelihatan wajar, gimana caranya jadi sinyal yang layak dilihat analis.

Sesuai filosofi lab: **deteksi dulu, bukan eksploitasi.**

---

## Prerequisites

- **Sysmon terpasang & jalan di Win7** — lihat [`win7-sysmon.md`](../../../../../Infrastructure/win7-sysmon.md).
- **Wazuh Agent di Win7 Active** — lihat [`win7-wazuh-agent.md`](../../../../../Infrastructure/win7-wazuh-agent.md).
- **Akun domain biasa** di Win7. Lab ini pakai `lab\p.analyst`, **bukan** Administrator. Semua command discovery di bawah jalan tanpa elevated privilege, dan itu justru bagian dari masalahnya: attacker gak butuh admin buat recon.

---

## Step-by-Step

### 1. Jalankan command discovery berurutan

Dari `cmd.exe` sebagai `lab\p.analyst`, jalanin empat command ini berurutan dalam waktu kurang dari 30 detik:

```cmd
systeminfo
hostname
whoami
whoami /priv
```

| Command | Yang didapat attacker | Teknik |
|---------|-----------------------|--------|
| `systeminfo` | Versi OS + service pack, hotfix yang terpasang, domain, logon server, IP | T1082 |
| `hostname` | Nama host | T1082 |
| `whoami` | Akun yang lagi dipakai (`lab\p.analyst`) | T1033 |
| `whoami /priv` | Privilege token yang dimiliki akun itu | T1033 |

Output `systeminfo` sendiri udah ngasih banyak buat attacker. Di host ini kelihatan `Windows 7 Professional 6.1.7601 Service Pack 1`, **cuma 2 hotfix** yang terpasang (`KB2534111`, `KB976902`), domain `lab.local` dengan logon server `\\WIN-AD-DC01`, dan IP `10.10.20.10`. Daftar hotfix yang pendek itu langsung jadi petunjuk exploit mana yang masih kebuka. `whoami /priv` nunjukin akun ini gak punya privilege berbahaya (cuma `SeChangeNotifyPrivilege` yang `Enabled`), jadi langkah attacker berikutnya kemungkinan privilege escalation.

![systeminfo, hostname, whoami, dan whoami /priv di cmd Win7](<./assets/cmd discovery commands.png>)

---

## Verifikasi

### A. Event masuk Wazuh, tapi gak ada alert

Tiap command di atas bikin **Sysmon event 1** (Process Create) dan sampai ke Manager. Tapi sama kayak di lab [T1059.001](<../../Execution/Command and Scripting Interpreter (T1059.001 - PowerShell)/README.md>) dan T1053.005, rule bawaan Sysmon event 1 (`61603`) itu level 0, jadi event-nya cuma kelihatan di `wazuh-archives-*`, gak jadi alert.

Rule bawaan buat discovery di `0800-sysmon_id_1.xml` juga gak bisa diandelin di host ini. Sebagian besar rule bawaan Sysmon event 1 nyantol ke field `originalFileName`, yang **gak dikirim Sysmon 4.0** di Win7 (temuan dari lab T1053.005).

Di archives, event-nya kelihatan jelas dengan command line utuh:

| Time (Dashboard) | `commandLine` | `image` |
|------------------|---------------|---------|
| 2026-09-26 22:06:45.175 | `systeminfo` | `C:\Windows\System32\systeminfo.exe` |
| 2026-09-26 22:06:45.183 | `C:\Windows\system32\wbem\wmiprvse.exe -secured -Embedding` | `C:\Windows\System32\wbem\WmiPrvSE.exe` |
| 2026-09-26 22:06:47.176 | `C:\Windows\system32\wbem\wmiprvse.exe -secured -Embedding` | `C:\Windows\System32\wbem\WmiPrvSE.exe` |
| 2026-09-26 22:07:05.171 | `hostname` | `C:\Windows\System32\HOSTNAME.EXE` |
| 2026-09-26 22:07:09.162 | `whoami` | `C:\Windows\System32\whoami.exe` |
| 2026-09-26 22:07:13.152 | `whoami /priv` | `C:\Windows\System32\whoami.exe` |

![Event Sysmon 1 command discovery di wazuh-archives-*](<./assets/archives sysmon 1 discovery.png>)

Dua hal kecil yang kelihatan di sini:

- **`systeminfo` nge-spawn `WmiPrvSE.exe`.** Dua proses `wmiprvse.exe -secured -Embedding` muncul 8 ms dan 2 detik setelah `systeminfo`. `systeminfo` ngambil sebagian datanya lewat WMI, jadi Windows ngidupin WMI provider host. Di tabel ini hubungan keduanya cuma kebaca dari waktunya. `parentImage` `WmiPrvSE.exe` belum dicek.
- **Nama file `HOSTNAME.EXE` huruf besar semua.** Rule yang nyocokin `image` harus case-insensitive.

### B. Custom rule 100607 — satu command discovery

Rule turunan `61603` yang naikin event 1 dari binary discovery jadi alert. Disimpan di repo: [`Detection-Engineer/wazuh/rule/sysmon_rules.xml`](../../../../../Detection-Engineer/wazuh/rule/sysmon_rules.xml).

```xml
<rule id="100607" level="3">
    <if_sid>61603</if_sid>
    <field name="win.system.eventID" type="pcre2">^1$</field>
    <field name="win.eventdata.image" type="pcre2">(?i)\\(systeminfo|hostname|net1?|whoami)\.exe$</field>
    <description>Sysmon: Discovery command execution detected (systeminfo/hostname/net/whoami)</description>
    <mitre>
        <id>T1082</id>
        <id>T1033</id>
        <id>T1087.001</id>
    </mitre>
    <group>discovery,discovery_recon,</group>
</rule>
```

| Field | Fungsi |
|-------|--------|
| `eventID` `^1$` | Process Create |
| `image` `\\(systeminfo\|hostname\|net1?\|whoami)\.exe$` | Binary discovery bawaan Windows. `(?i)` nutup `HOSTNAME.EXE`. `net1?` nutup `net.exe` dan `net1.exe`, karena `net user` di Win7 nge-spawn `net1.exe` buat ngerjain kerjaan aslinya |
| `mitre` T1082 + T1033 + T1087.001 | `systeminfo`/`hostname` → T1082, `whoami` → T1033, `net user` → T1087.001. `net` ada di rule tapi gak dijalanin di run lab ini |
| `group` `discovery_recon` | Penanda buat dihitung rule korelasi `100608` |

**Kenapa level 3.** Satu command discovery doang itu hampir gak ada artinya. Admin ngetik `hostname` dan `whoami` tiap hari, script login dan software inventory manggil `systeminfo`. Kalau tiap command dijadiin alert tinggi, Dashboard penuh false positive. Jadi `100607` sengaja level rendah. Fungsinya lebih ke **jejak** yang bisa dicari pas investigasi, plus jadi bahan hitungan buat `100608`. Level 3 juga di bawah threshold Integrator (`≥7`), jadi gak ikut ke n8n, Jira, atau Discord.

### C. Custom rule 100608 — banyak command discovery dalam waktu singkat

Yang bikin discovery mencurigakan itu **polanya**: beberapa command recon beda dalam hitungan detik. Itu kelakuan orang (atau script) yang lagi ngenalin host baru, bukan kerjaan harian admin.

```xml
<rule id="100608" level="10" frequency="3" timeframe="30">
    <if_matched_group>discovery_recon</if_matched_group>
    <description>Multiple discovery commands executed within short timeframe (possible recon burst activity)</description>
    <mitre>
        <id>T1082</id>
        <id>T1033</id>
        <id>T1087</id>
    </mitre>
    <group>discovery,recon_burst,</group>
</rule>
```

| Opsi | Fungsi |
|------|--------|
| `if_matched_group` `discovery_recon` | Yang dihitung alert dari group `discovery_recon`, yaitu `100607` |
| `frequency` `3` | Fire kalau udah ada 3 alert `discovery_recon` |
| `timeframe` `30` | Dalam jendela 30 detik |

Ini rule **frequency** pertama di project ini. Rule korelasi sebelumnya (`100602`, `100604`) nyambungin dua event yang **beda jenis** (event 1 + event 3, event 1 + 4698). `100608` beda: dia ngitung event yang **sejenis** sampai lewat ambang tertentu.

### D. Hasil — alert live di Wazuh Dashboard

| Time (Dashboard) | Rule | Level | `image` |
|------------------|------|-------|---------|
| 2026-09-26 22:06:45.175 | `100607` | 3 | `C:\Windows\System32\systeminfo.exe` |
| 2026-09-26 22:07:05.171 | `100607` | 3 | `C:\Windows\System32\HOSTNAME.EXE` |
| 2026-09-26 22:07:09.162 | `100608` | 10 | `C:\Windows\System32\whoami.exe` |

![Alert 100607 dan 100608 di wazuh-alerts-*](<./assets/alerts 100607 100608 run pertama.png>)

Yang bisa dibaca dari tabel ini:

- **`100608` fire di command ketiga.** `systeminfo` (22:06:45) dan `hostname` (22:07:05) jadi `100607`, lalu `whoami` (22:07:09) jadi `100608`. Jarak command pertama ke ketiga **24 detik**, masih di dalam `timeframe` 30. Jadi di Wazuh 4.13, `frequency="3"` artinya 3 event **termasuk** event yang lagi diproses.
- **Alert `whoami` ber-ID `100608`, bukan `100607`.** Ini aturan satu-event-satu-alert yang sama dengan temuan di lab T1053.005: `100608` nempel di atas `100607` lewat `if_matched_group`, jadi waktu dia match, dia **nggantiin** alert `100607` buat event itu. Konsekuensinya bagus buat analis: alert level 10 itu sendiri bawa `image` dan `commandLine` dari command yang bikin ambangnya kelewat.
- **`whoami /priv` (22:07:13) gak kelihatan di screenshot alert.** Screenshot diambil 22:07:21, 8 detik setelah event-nya. Di archives event-nya ada. ⚠️ Belum dicek apakah dia jadi alert (`100607` atau `100608`) dan cuma belum ke-index waktu screenshot diambil, atau emang gak jadi alert.

> **Catatan evidence:** screenshot cmd (`cmd discovery commands.png`, jam Win7 22:21) dan screenshot Dashboard (22:06–22:07) berasal dari **run yang berbeda**. Di cmd, command keempat diketik `whoami/priv` (tanpa spasi), sementara di archives tercatat `whoami /priv`. Urutan command-nya sama.

### E. Batasan

- **Gak ada filter `parentImage`.** `100607` match siapa pun yang jalanin binary itu, termasuk script login, software inventory, atau tool monitoring. Di lab ini aman, di lingkungan nyata `100608` bakal fire tiap ada script yang manggil 3 command itu berurutan. Kandidat whitelist baru bisa ditentuin setelah liat baseline host yang normal.
- **Belum ada `same_field`.** `100608` ngitung semua alert `discovery_recon` dalam 30 detik tanpa syarat datang dari proses atau user yang sama. Dua user beda yang kebetulan masing-masing ngetik `whoami` bisa ikut kehitung jadi satu burst. Di lab ini cuma `WIN7-VICTIM` yang kirim Sysmon, jadi belum kelihatan. Apakah frequency rule Wazuh otomatis nge-scope per-agent juga **belum diuji**. → Ditangani di [section F](#f-revisi-rule--bug-yang-ketemu-setelah-run-pertama) dengan `same_field win.eventdata.user`.
- **Cuma binary yang ada di daftar.** Discovery lewat PowerShell (`Get-ComputerInfo`, `[Environment]::UserName`), WMI (`wmic os get`), atau `set` / `echo %USERNAME%` di cmd gak nyentuh `systeminfo`/`whoami`/`net`, jadi gak ketangkep. Recon juga bisa dipecah: 2 command, jeda 31 detik, 2 command lagi, dan `100608` gak pernah fire. → Sempat dicoba tier recon pelan `100610`, lalu dihapus. Lihat section F.
- **Level 10 berarti ikut ke Discord.** `100608` lolos threshold Integrator (`≥7`), dan karena node IF filter group `notify_discord` di n8n belum dibikin (lihat lab T1053.005 section F), semua alert level ≥7 masih ikut ke Discord.


### F. Revisi rule — bug yang ketemu setelah run pertama

Setelah `100608` fire di run pertama, rule-nya diuji lagi dengan pertanyaan yang lebih jahat. Ketemu empat masalah.

#### Bug 1: satu command diulang 3× udah dianggap burst

Ngetik `whoami` **3 kali** berturut-turut bikin `100608` versi pertama fire. Padahal itu bukan recon, cuma satu command yang diulang. Mungkin user lagi ngecek apakah dia udah logon sebagai akun yang bener.

Sebabnya, `frequency="3"` cuma ngitung **berapa kali** alert `discovery_recon` muncul. Dia gak peduli alert-alert itu dari command yang sama atau beda. Yang mau dideteksi sebenernya **variasi**: orang yang nanya "host apa", "OS apa", "saya siapa", "privilege saya apa" dalam waktu singkat.

Fix-nya `<different_field>`, dan butuh dua percobaan buat nemu field yang pas (hasilnya di bagian [Hasil tes](#hasil-tes)).

#### Bug 2: burst dari user yang beda ikut kehitung

`100608` versi pertama ngitung semua alert `discovery_recon` di jendela 30 detik, dari siapa aja. User A ngetik `hostname` dan user B ngetik `whoami` bisa jadi satu "burst" palsu. Fix-nya `<same_field>win.eventdata.user</same_field>`. Efek sampingnya bagus: tiap alert burst dijamin nunjuk ke **satu user**, jadi analis langsung tahu siapa yang diinvestigasi.

User itu juga ditaruh di description `100607` dan `100609` lewat field dinamis `$(win.eventdata.user)`, jadi kelihatan di kolom description Dashboard tanpa harus expand alert.

#### Bug 3: recon yang pelan lolos

Jendela 30 detik cuma nangkep orang yang ngetik cepat. Attacker yang sabar, misalnya satu command tiap 10 menit, gak akan pernah bikin `100608` fire. `timeframe` 100608 gak dilebarin, karena itu bakal nyampurin burst cepat dengan aktivitas harian admin.

Sempat dibikin tier kedua `100610` (`frequency="5"`, `timeframe="3600"`, level 8) dengan `different_field` yang sama. **Rule itu akhirnya dihapus**, karena dua hal:
- Dia kena masalah `different_field` yang sama kayak `100608` (lihat Hasil tes): yang dijamin cuma "event sekarang beda dari event-event sebelumnya", bukan "semua command unik".
- Waktu itu `different_field`-nya masih `image`, dan daftar binary di `100607` isinya persis 5 (`systeminfo`, `hostname`, `whoami`, `net.exe`, `net1.exe`). Kalau `different_field` beneran ngitung yang unik, `frequency="5"` artinya rule cuma fire kalau **semua** binary dijalanin.

Recon pelan sekarang **jadi gap yang terdokumentasi**. Ngitung command unik per user dalam jendela panjang lebih cocok di layer korelasi API (Fase 2), yang bisa query alert `100607` dari Indexer lalu ngitung `image` yang beda-beda dengan logic biasa.

#### Bug 4: jam kejadian gak diperhitungin

Burst recon jam 23:00 lebih mencurigakan daripada jam 10:00. Bobot ini ditaruh **di rule Wazuh**, bukan di n8n. Alasannya, alert yang sama dibaca tiga konsumen (Dashboard, Jira, Discord). Kalau severity cuma dinaikin di n8n, yang tahu alert-nya berat cuma Discord, sementara Dashboard dan Jira tetap nganggep level 10 biasa. Severity harus melekat di alert-nya, n8n cukup ngurus cara nampilin.

Wazuh punya opsi `<time>` di rule. Rule anak `100609` nempel di `100608` dan cuma match di jam tertentu. Di sini aturan satu-event-satu-alert justru dipakai dengan sengaja: di luar jam kerja alert burst **diganti** jadi `100609` level 12, di jam kerja tetap `100608` level 10.

**Gotcha: `<time>` pakai jam Manager, bukan jam Win7.** Dell jalan di `Etc/UTC`:

```
root@Wazuh:/home/anang# timedatectl
                Time zone: Etc/UTC (UTC, +0000)
```

Draft pertama pakai `<time>6 pm - 7 am</time>`. Di Manager UTC, itu artinya 01:00–14:00 WIB, **kebalik total**: jam kerja siang malah dianggap off-hours. Off-hours 18:00–07:00 WIB dikonversi ke UTC jadi 11:00–00:00. Batas akhirnya ditulis `23:59`, bukan `00:00`, biar gak ambigu tengah malam dibaca sebagai "hari berikutnya" atau "sepanjang hari". Harganya kelewat 1 menit (06:59–07:00 WIB).

Timezone Dell sengaja **gak** diganti ke WIB. SIEM di UTC itu praktik standar, dan layer korelasi API (`/notify/cross-decoder`) selama ini bekerja dengan timestamp `+0000`. Kalau timezone diganti di tengah jalan, alert lama dan baru jadi campuran `+0000` dan `+0700`.

#### Rule setelah revisi

```xml
<rule id="100607" level="3">
    <if_sid>61603</if_sid>
    <field name="win.system.eventID" type="pcre2">^1$</field>
    <field name="win.eventdata.image" type="pcre2">(?i)\\(systeminfo|hostname|net1?|whoami)\.exe$</field>
    <description>Sysmon: Discovery command execution detected (systeminfo/hostname/net/whoami) by $(win.eventdata.user)</description>
    <mitre>
        <id>T1082</id>
        <id>T1033</id>
        <id>T1087.001</id>
    </mitre>
    <group>discovery,discovery_recon,</group>
</rule>
<rule id="100608" level="10" frequency="3" timeframe="30">
    <if_matched_group>discovery_recon</if_matched_group>
    <different_field>win.eventdata.commandLine</different_field>
    <same_field>win.eventdata.user</same_field>
    <description>Multiple discovery commands executed within short timeframe (possible recon burst activity)</description>
    <mitre>
        <id>T1082</id>
        <id>T1033</id>
        <id>T1087</id>
    </mitre>
    <group>discovery,recon_burst,</group>
</rule>
<rule id="100609" level="12">
    <if_sid>100608</if_sid>
    <time>11:00 - 23:59</time>
    <description>Recon burst outside business hours by $(win.eventdata.user)</description>
    <mitre>
        <id>T1082</id>
        <id>T1033</id>
        <id>T1087</id>
    </mitre>
    <group>discovery,recon_burst,off_hours,</group>
</rule>
```

| Rule | Level | Syarat | Pertanyaan yang dijawab |
|------|-------|--------|-------------------------|
| `100607` | 3 | 1 command discovery | Jejak investigasi |
| `100608` | 10 | 3 alert `discovery_recon`, `commandLine` beda dari event sebelumnya, user sama, dalam 30 detik | Ada recon cepat? |
| `100609` | 12 | `100608` + jam 18:00–06:59 WIB (11:00–23:59 UTC) | Recon cepat di luar jam kerja? |

`100609` bawa `<mitre>` dan `<group>` sendiri karena rule anak gak mewarisi keduanya dari rule induk. Tanpa itu, alert off-hours hilang dari filter `rule.groups: discovery` di Dashboard.

#### Hasil tes

Semua tes jalan malam 26 September 2026 (±23:00 WIB = ±16:00 UTC), jadi masih di dalam jendela `<time>`. Karena itu burst yang kedeteksi muncul sebagai **`100609`**, bukan `100608`.

**Percobaan 1 — `different_field` = `win.eventdata.image`**

| Urutan | Hasil |
|--------|-------|
| `whoami` ×3 | Cuma tiga `100607`. Gak ada burst ✅ |
| lanjut `whoami /priv`, lalu `hostname` | Burst fire di `hostname` ❌ |

Di jendela 30 detik itu `image` yang unik cuma **dua**: `whoami.exe` (4×) dan `HOSTNAME.EXE`. Tapi rule-nya tetap fire. Dari sini kebaca cara kerja `different_field`: event yang **sekarang** dibandingin sama tiap event sebelumnya. Pas `hostname` masuk, empat `whoami` sebelumnya sama-sama beda dari `hostname`, jadi semuanya kehitung. Event-event sebelumnya **gak** dibandingin satu sama lain. Jadi yang dijamin cuma "minimal 2 command beda", bukan 3.

**Percobaan 2 — `different_field` = `win.eventdata.commandLine`** (versi yang dipakai sekarang)

| Time (Dashboard) | Rule | Level | `commandLine` | `image` |
|------------------|------|-------|---------------|---------|
| 2026-09-26 23:18:02.115 | `100607` | 3 | `whoami` | `whoami.exe` |
| 2026-09-26 23:18:18.118 | `100607` | 3 | `whoami` | `whoami.exe` |
| 2026-09-26 23:18:22.187 | `100607` | 3 | `whoami` | `whoami.exe` |
| 2026-09-26 23:18:50.119 | `100607` | 3 | `net  localgroup` | `net.exe` |
| 2026-09-26 23:18:50.133 | `100607` | 3 | `C:\Windows\system32\net1  localgroup` | `net1.exe` |
| 2026-09-26 23:19:12.121 | **`100609`** | **12** | `hostname` | `HOSTNAME.EXE` |

![whoami 3x cuma jadi 100607, gak ada burst](<./assets/test whoami 3x tanpa burst.png>)

![net localgroup + hostname jadi 100609](<./assets/test net localgroup hostname 100609.png>)

Yang kebaca dari tabel ini:

- **`whoami` 3× tetap gak jadi burst.** `commandLine`-nya identik, jadi `different_field` nolak.
- **Burst di `hostname` (23:19:12) cuma dihitung dari event di 30 detik terakhir**, yaitu 23:18:42 ke atas: `net.exe`, `net1.exe`, dan `hostname`. Tiga `whoami` (23:18:02–23:18:22) udah di luar jendela.
- **Tiga event itu cuma dari DUA command yang diketik.** `net localgroup` di Win7 ngejalanin `net.exe`, lalu `net.exe` nge-spawn `net1.exe` buat ngerjain kerjaan aslinya. Dua-duanya match regex `net1?` di `100607`, dan `commandLine`-nya beda (`net  localgroup` vs `C:\Windows\system32\net1  localgroup`). Jadi satu `net` + satu command lain udah cukup buat bikin burst.
- **`100609` gantiin `100608`** sesuai desain, karena jam 23:19 WIB = 16:19 UTC ada di dalam `11:00 - 23:59`.

**Kenapa `commandLine` lebih cocok daripada `image`.** Dua-duanya tetap cuma bandingin event sekarang sama tiap event sebelumnya, jadi kelemahan dasarnya sama. Bedanya ada di kasus satu tool dengan flag yang beda:

| Urutan | `image` | `commandLine` |
|--------|---------|---------------|
| `whoami` ×3 | gak fire | gak fire |
| `whoami`, `whoami /priv`, `whoami /groups` | gak fire | fire |
| `whoami` ×2 + `hostname` | fire | fire |

Baris tengah itu yang bikin `commandLine` lebih pas. Gonta-ganti flag `whoami` (`/priv`, `/groups`, `/all`) itu pola recon: nanya hal yang beda ke tool yang sama. Harganya, `commandLine` gampang di-vary. `whoami`, `WHOAMI`, `whoami.exe`, atau `whoami` plus spasi di belakang kebaca empat command line yang beda. Jadi satu command yang diulang dengan variasi kecil bisa bikin rule ini fire.

#### Batasan yang tersisa

- **`different_field` gak ngitung command yang unik.** Jaminan `100608` yang sebenarnya: minimal 2 `commandLine` beda dalam 3 event. Wazuh gak punya cara native buat ngitung yang unik di frequency rule.
- **`net` dihitung dua kali.** Satu `net user` / `net localgroup` = dua alert `100607` (`net.exe` + `net1.exe`). Kalau mau satu command dihitung sekali, `net1?` di regex `100607` perlu dipecah, atau `net1.exe` dengan parent `net.exe` dikecualikan. Belum diubah.
- **Recon pelan** gak ada rule-nya (`100610` dihapus). Kandidat buat layer API Fase 2.

---

## Kesimpulan

Discovery di Win7 pakai command bawaan (`systeminfo`, `hostname`, `whoami`) **gak kelihatan sama sekali** di Wazuh secara default. Event Sysmon 1-nya sampai ke Manager, tapi berhenti di rule bawaan `61603` yang level 0, dan rule discovery bawaan yang nyantol ke `originalFileName` gak bisa jalan karena Sysmon 4.0 gak ngirim field itu.

Gap itu ditutup dua lapis. `100607` naikin tiap command discovery jadi alert level 3: cukup buat jadi jejak investigasi, tapi gak bikin Dashboard berisik. `100608` baru naikin severity ke level 10 kalau ada **3 command discovery dalam 30 detik**, karena yang mencurigakan dari discovery itu polanya, bukan command satuannya. Run 26 September 2026 nunjukin `100608` fire tepat di command ketiga (`whoami`), 24 detik setelah `systeminfo`.

Pelajaran utamanya soal cara ngukur sinyal yang lemah. Buat teknik yang command-nya juga dipakai admin tiap hari, deteksi per-event gak bakal pernah bersih. Yang bisa dipakai itu **kepadatan**: berapa banyak, seberapa rapat, dari siapa. Revisi rule (section F) nambahin yang ketiga lewat `same_field win.eventdata.user`, plus bobot waktu lewat rule anak `100609` yang naikin burst di luar jam kerja ke level 12. Waktu revisi ketemu satu gotcha operasional: `<time>` dibaca pakai jam Manager, dan Dell jalan di UTC. Jadi jendela off-hours WIB harus ditulis dalam UTC.

Soal "berapa banyak", ternyata Wazuh gak bisa ngitung yang **unik**. `different_field` cuma bandingin event yang sekarang sama tiap event sebelumnya. Dengan `commandLine`, `whoami` yang diulang 3× gak lagi jadi burst, tapi jaminan rule-nya tetap cuma "minimal 2 command beda". Satu `net localgroup` pun udah ngasilin dua event (`net.exe` + `net1.exe`), dan tes malam 26 September nunjukin `net localgroup` + `hostname` udah cukup buat bikin `100609`. Batasan ini, bareng recon pelan yang rule-nya (`100610`) dihapus, lebih cocok diselesaiin di layer korelasi API daripada dipaksa di rule Wazuh.
