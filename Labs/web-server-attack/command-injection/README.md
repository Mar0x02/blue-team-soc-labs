# Command Injection — DVWA (Web-Server)

## Tujuan

Simulasi manual **Command Injection** ke modul **Command Injection** DVWA (`10.10.10.10`) dari Kali Linux, sekaligus validasi: apakah request **POST** (beda dari SQL Injection yang GET) tetep bisa dianalisa lewat `access.log` dan ke-detect Wazuh. Sesuai filosofi lab: deteksi dulu, bukan eksploitasi.

---

## Prerequisites

- DVWA sudah bisa diakses dari Kali — lihat [`dvwa-external-access.md`](../../../Infrastructure/dvwa-external-access.md)
- Wazuh Agent di Web-Server sudah running, sudah baca `/var/log/apache2/access.log` — lihat [`web-server-wazuh-agent.md`](../../../Infrastructure/web-server-wazuh-agent.md)
- DVWA **Security Level** di-set ke `Low`

---

## Step-by-Step

Modul **Command Injection** DVWA nerima input IP address, di-backend dijalanin lewat `shell_exec()`/`system()` buat nge-ping IP itu. Karena input user gak disanitasi, bisa disisipin command tambahan pakai separator `;`.

### 1. Command Chaining — Info Dasar Sistem

```
127.0.0.1; whoami
```
Output: `www-data`

```
127.0.0.1; id
```
Output: `uid=33(www-data) gid=33(www-data) groups=33(www-data)`

```
127.0.0.1; echo "Vuln"
```
Output: `Vuln`

![Command injection attempt + access log + Wazuh dashboard](./asset/01-command-injection-blindspot.gif)

### 2. Percobaan Tulis File

```
127.0.0.1; echo "Testing make some file" > /var/www/html/test.txt
```

Gak ada output di halaman (wajar — `echo` di-redirect ke file, bukan ke stdout). File berhasil ke-buat di web root, bisa diverifikasi langsung.

![Percobaan tulis file ke /var/www/html](./asset/02-outfile-file-write-test.gif)

---

## Verifikasi

| Cek | Hasil |
|---|---|
| Command tereksekusi di server? | ✅ Ya — semua command (`whoami`, `id`, `echo`, file write) berhasil |
| Payload tercatat di `access.log`? | ❌ **Tidak** — cuma tercatat `POST /vulnerabilities/exec/ HTTP/1.1`, tanpa command yang dikirim |
| Ke-detect di Wazuh Dashboard? | ❌ **Tidak** — silent, gak ada alert sama sekali |

**Root cause:** modul ini pakai method **POST**, beda dari SQL Injection (GET) yang parameternya nampil di URL. Apache **Combined Log Format** (format default `access.log`) cuma nyatet method + path + status code — **isi body POST gak pernah ke-log**. Jadi bukan soal rule Wazuh kurang tajam (kayak gap SQLi kemarin), ini **blind spot infrastruktur**: bahan mentah buat dianalisa emang gak pernah nyampe ke SIEM sama sekali.

---

## Kesimpulan

1. **Command Injection berhasil dieksekusi penuh** — dari info dasar (`whoami`, `id`) sampai **arbitrary file write** ke web root, gak ada hambatan sama sekali di modul ini (beda sama percobaan `INTO OUTFILE` di lab SQLi yang kena block privilege).
2. **Blind spot kritis**: request POST secara struktural gak ninggalin jejak payload di `access.log` standar. Attacker bisa jalanin command apapun lewat form ini tanpa ninggalin bukti forensik di log Apache — jauh lebih berbahaya dibanding gap SQLi kemarin (yang setidaknya payload-nya masih kecatet, cuma rule-nya yang kurang).
3. Opsi nutup gap dari sisi **Web-Server/aplikasi** (`mod_dumpio`, ModSecurity buat log POST body) dipertimbangkan tapi **effort-nya berat** relatif ke manfaatnya untuk skala lab ini. Pendekatan yang dipilih: tambah **NIDS (Suricata/Snort) di pfSense** sebagai lapis deteksi network-wide yang independen dari limitasi logging tiap aplikasi — dibahas terpisah sebagai task infrastruktur.

---

## Reverse Shell (Belum Dikerjakan)

*Section ini sengaja dikosongin — rencana lanjutan dari Command Injection ini buat coba dapetin reverse shell, menyusul di sesi berikutnya.*
