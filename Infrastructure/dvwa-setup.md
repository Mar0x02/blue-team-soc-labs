# DVWA Setup — Damn Vulnerable Web Application

## Tujuan

Install **DVWA (Damn Vulnerable Web Application)** di atas LAMP stack (Apache + MariaDB + PHP) pada VM Web-Server (`10.10.10.10`), jadi target web attack untuk skenario deteksi SQL Injection, XSS, Command Injection, Brute Force, dll yang nantinya dideteksi Wazuh.

---

## Prerequisites

- VM Web-Server sudah terinstall Ubuntu Server 26.04 LTS dengan static IP `10.10.10.10/24` — lihat [`web-server-setup.md`](./web-server-setup.md)
- Konektivitas ke gateway (`10.10.10.1`) dan internet sudah terverifikasi
- Akses SSH atau console ke VM Web-Server

---

## Step 1 — Install LAMP Stack

```bash
sudo apt update && sudo apt upgrade -y

# Apache + MariaDB
sudo apt install apache2 mariadb-server -y

# PHP + ekstensi yang dibutuhkan DVWA
sudo apt install php libapache2-mod-php php-mysqli php-gd php-cli php-common php-curl php-xml php-mbstring -y
```

Cek versi PHP yang terinstall:

```bash
php -v
```

> **Catatan versi PHP:** Ubuntu 26.04 ship PHP 8.5. DVWA versi terbaru dari [digininja/DVWA](https://github.com/digininja/DVWA) sudah kompatibel dengan PHP 8.x. Kalau nanti muncul error terkait `mysqli` atau deprecated function saat load DVWA, itu wajar untuk kode lama — catat errornya dan kita fix sambil jalan.

---

## Step 2 — Clone DVWA

```bash
cd /var/www/html
sudo rm index.html   # hapus default Apache page

sudo apt install git -y
sudo git clone https://github.com/digininja/DVWA.git .
```

Set ownership ke user Apache:

```bash
sudo chown -R www-data:www-data /var/www/html
```

---

## Step 3 — Konfigurasi Database MariaDB

```bash
sudo mariadb-secure-installation
```

> **Catatan nama command:** Versi MariaDB yang di-ship Ubuntu 26.04 pakai nama `mariadb-secure-installation` (bukan `mysql_secure_installation` di versi lama). Cek dulu command mana yang tersedia: `ls /usr/bin/ | grep -i secure`.

Ikuti prompt:
- Switch to unix_socket authentication? → **n** (biar `mysql -u root -p` konsisten pakai password)
- Change the root password? → **Y**, set password baru
- Remove anonymous users? → **Y**
- Disallow root login remotely? → **Y**
- Remove test database and access to it? → **Y**
- Reload privilege tables now? → **Y**

Buat database dan user khusus DVWA:

```bash
sudo mysql -u root -p
```

```sql
CREATE DATABASE dvwa;
CREATE USER 'dvwa'@'localhost' IDENTIFIED BY 'p@ssw0rd_dvwa';
GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

> **Catatan:** Password `p@ssw0rd_dvwa` cuma contoh — ganti sesuka hati, ini database lab lokal jadi gak masuk `.gitignore`/credential file manapun. Tapi tetap jangan sama dengan password akun real manapun.

---

## Step 4 — Konfigurasi DVWA config.inc.php

```bash
cd /var/www/html/config
sudo cp config.inc.php.dist config.inc.php
sudo nano config.inc.php
```

Sesuaikan bagian database:

```php
$_DVWA[ 'db_server' ]   = '127.0.0.1';
$_DVWA[ 'db_database' ] = 'dvwa';
$_DVWA[ 'db_user' ]     = 'dvwa';
$_DVWA[ 'db_password' ] = 'p@ssw0rd_dvwa';
$_DVWA[ 'db_port' ]     = '3306';
```

---

## Step 5 — Konfigurasi PHP (php.ini)

DVWA butuh beberapa setting PHP yang default-nya off demi security — di lab ini kita aktifkan sengaja karena tujuannya jadi **vulnerable target**:

> **Penting:** Cari path php.ini untuk SAPI **apache2**, bukan **cli** — `php --ini` dari terminal nunjukkin config CLI, gak kepake sama Apache. Path Apache biasanya `/etc/php/8.5/apache2/php.ini`.

Cara cepat pakai `sed` (lebih cepat daripada scroll manual di editor):

```bash
sudo sed -i.bak -E \
  -e 's/^;?\s*allow_url_include\s*=.*/allow_url_include = On/' \
  -e 's/^;?\s*allow_url_fopen\s*=.*/allow_url_fopen = On/' \
  -e 's/^;?\s*display_errors\s*=.*/display_errors = On/' \
  /etc/php/8.5/apache2/php.ini
```

Verifikasi:

```bash
grep -E "^(allow_url_include|allow_url_fopen|display_errors)" /etc/php/8.5/apache2/php.ini
```

Restart Apache setelah edit:

```bash
sudo systemctl restart apache2
```

---

## Step 6 — Set Permission Folder

DVWA butuh folder `hackable/uploads` writable oleh Apache (dipakai skenario unrestricted file upload):

```bash
sudo chmod -R 777 /var/www/html/hackable/uploads
```

> **Catatan:** `chmod 777` biasanya red flag di production, tapi di sini memang requirement DVWA supaya vulnerable folder bisa ditulis web server.

> **Catatan folder phpids:** Versi DVWA yang lebih baru (`digininja/DVWA`) sudah tidak menyertakan `external/phpids` — kalau folder itu gak ada di clone-an kamu (cek `ls external/` dan `.gitmodules`), skip aja, tidak perlu di-chmod.

---

## Step 7 — Setup via Browser

Dari VM Web-Server sendiri (atau device lain di LAN1 yang sudah bisa reach `10.10.10.10`):

```
http://10.10.10.10/setup.php
```

1. Halaman **DVWA Setup** akan cek semua requirement (PHP module, folder writable, dll) — pastikan semua **green**
2. Scroll ke bawah → klik **Create / Reset Database**
3. Tunggu sampai selesai → otomatis redirect ke halaman login

---

## Step 8 — Login & Set Security Level

```
URL       : http://10.10.10.10/login.php
Username  : admin
Password  : password
```

Setelah login, buka **DVWA Security** di sidebar → pilih security level:

| Level | Kegunaan |
|-------|----------|
| **Low** | Vulnerability paling jelas, cocok untuk verifikasi awal apakah Wazuh bisa detect payload dasar |
| **Medium** | Ada filter parsial, simulasi bypass sederhana |
| **High** | Filter lebih ketat, butuh teknik bypass advanced |
| **Impossible** | Kode aman sepenuhnya (baseline pembanding "before/after" fix) |

> Ganti password default admin/password sebelum lab dipakai lebih lanjut, meskipun ini environment isolated.

---

## Verifikasi

### Dari VM Web-Server sendiri:

```bash
curl -I http://localhost/login.php
# harus return HTTP 200 OK
```

### Dari browser di device lain di LAN1 (kalau ada):

```
http://10.10.10.10/login.php   → harus muncul halaman login DVWA
```

### Cek service jalan:

```bash
sudo systemctl status apache2   # active (running)
sudo systemctl status mariadb   # active (running)
```

---

## Troubleshooting

| Masalah | Kemungkinan Penyebab | Solusi |
|---------|----------------------|--------|
| Setup page banyak merah (`allow_url_include` disabled, dll) | php.ini belum diubah / Apache belum restart | Ulangi Step 5, pastikan `sudo systemctl restart apache2` |
| `Unable to connect to the database` | Kredensial di `config.inc.php` salah, atau MariaDB belum jalan | Cek `sudo systemctl status mariadb`, cocokkan user/password di Step 3 & 4 |
| Halaman blank / 500 error | Versi PHP terlalu baru untuk kode DVWA (deprecated function) | Cek Apache error log: `sudo tail -f /var/log/apache2/error.log` |
| Folder upload gagal writable | Permission belum di-set | Ulangi Step 6, atau cek `ls -la` folder terkait |

---

## Catatan Keamanan Lab

DVWA ini **sengaja vulnerable** — jangan expose ke internet langsung. Karena Web-Server ada di LAN1 di belakang pfSense (bukan di WAN), exposure default sudah terbatas. Untuk skenario attack dari Kali (external attacker di WAN/hotspot), akses ke DVWA butuh firewall/NAT rule tambahan di pfSense — ini akan dikonfigurasi terpisah saat mulai skenario attack spesifik, supaya exposure-nya terkontrol dan cuma aktif saat lab attack berjalan.

---

## Selanjutnya

Web-Server + DVWA siap jadi target. Lanjut ke VM berikutnya sesuai urutan di [`pfsense-setup.md`](./pfsense-setup.md#selanjutnya):

**LAN1 — Server Zone:**
- **WIN AD** (`10.10.10.20`) — Windows Server + Active Directory

**LAN2 — Host Zone:**
- Windows 7, Windows XP, Ubuntu Host

Setelah semua VM infrastructure jadi, baru integrasi **Wazuh Agent** di tiap VM dan setup firewall rule spesifik untuk skenario attack dari Kali.
