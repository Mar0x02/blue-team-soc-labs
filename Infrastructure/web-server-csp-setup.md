# Web-Server — Setup CSP Report-Only + Integrasi Wazuh

## Tujuan

Pasang header **`Content-Security-Policy-Report-Only`** di Apache Web-Server (`10.10.10.10`, LAN1) buat nutup blind spot yang ketemu di lab [Stored XSS](../Labs/web-server-attack/xss/stored/README.md): momen **replay** (visitor lain buka halaman guestbook yang udah kena Stored XSS) gak ninggalin jejak apapun di request-nya sendiri, jadi gak ada layer detection berbasis analisa *request* (baik `access.log` maupun Suricata NIDS) yang bisa nangkep momen itu.

`Report-Only` dipilih (bukan mode *enforce*) karena sinyal yang dibutuhin datang dari **sisi browser korban**, bukan dari analisa traffic/log di server — begitu browser ngerender halaman dan ketemu resource yang melanggar policy, dia otomatis ngirim `POST` terpisah ke `report-uri` yang kita tentuin. Request kedua ini independen dari limitasi "gak ada payload di request korban", karena dia dipicu oleh **pelanggaran policy**, bukan oleh isi request awal. Mode ini juga sengaja gak nge-block apapun (browser tetep jalanin resource-nya kayak biasa) — murni nambah visibility, konsisten sama fokus lab yang masih di tahap *detection*.

---

## Prerequisites

- Web-Server base OS + DVWA sudah terinstall — lihat [`web-server-setup.md`](./web-server-setup.md) dan [`dvwa-setup.md`](./dvwa-setup.md)
- Wazuh Agent di Web-Server sudah terinstall dan **status Active**, baca `access.log` — lihat [`web-server-wazuh-agent.md`](./web-server-wazuh-agent.md)
- Referensi blind spot yang jadi basis kerjaan ini — lihat section ["Kesimpulan Stored XSS"](../Labs/web-server-attack/xss/stored/README.md#kesimpulan-stored-xss)

---

## Step-by-Step

### 1. Enable `mod_headers`

```bash
sudo a2enmod headers
sudo systemctl restart apache2
```

### 2. Tambah header CSP Report-Only — scope ke path yang rentan aja

```bash
sudo nano /etc/apache2/sites-available/000-default.conf
```

```apache
<VirtualHost *:80>
    ...
    <LocationMatch "^/vulnerabilities/(xss_s|xss_d)/">
        Header set Content-Security-Policy-Report-Only "default-src 'self'; script-src 'self' 'report-sample'; report-uri /csp-report.php"
    </LocationMatch>
</VirtualHost>
```

`script-src 'self'` sengaja ketat — inline `<script>` (persis payload guestbook di lab Stored XSS) **bukan** `'self'`, jadi violation-nya bakal ke-trigger tiap kali payload ke-*load* browser, baik di momen submit maupun replay.

`'report-sample'` ditambahin biar browser nyertain field `script-sample` di report — potongan kode yang kena block (di-truncate ~40 karakter sama browser demi keamanan, tapi cukup buat identifikasi payload-nya). Tanpa keyword ini, report cuma kasih tau *ada* pelanggaran, gak kasih tau *isinya* apa.

**Kenapa `<LocationMatch>`, bukan langsung di level `<VirtualHost>`:** kalau header-nya dipasang site-wide, CSP bakal ke-trigger di **halaman DVWA manapun** yang punya inline script/handler (DVWA sendiri sering pake ini buat UI-nya) — noise yang gak relevan sama sekali buat lab ini. Scope ke path yang emang lagi diuji doang bikin report yang masuk **cuma dari halaman yang relevan**.

> **Update 2026-07-23:** pattern `(xss_s|xss_d)` nambahin `/vulnerabilities/xss_d/` buat persiapan lab [DOM XSS](../Labs/web-server-attack/xss/dom/README.md) — validasi apakah CSP tetep bisa nangkep violation walau payload-nya dikirim lewat URL fragment (`#...`) yang gak pernah lewat network sama sekali.

```bash
sudo apache2ctl configtest
sudo systemctl reload apache2
```

> **Catatan noise lain (bukan bug):** kalau guestbook masih nyimpen beberapa payload dari test-test sebelumnya (belum di-reset DB), tiap payload yang masih ke-render bakal ngirim report-nya sendiri-sendiri per page load — jadi wajar liat beberapa report identik/mirip dalam satu request. Reset DB DVWA (`setup.php` → Create/Reset Database) dulu sebelum replay final kalau mau hasil yang bersih 1 payload = 1 report.

### 3. Bikin endpoint penampung report

> **Catatan method:** Browser CSP selalu ngirim report lewat `POST` — ini baku dari spec, gak bisa dikonfig jadi `GET`. Yang bisa kita atur cuma **isi endpoint-nya**: daripada cuma balikin `204` kosong, kita baca body `POST`-nya (JSON) dan log detailnya — termasuk `document-uri` (halaman yang lagi diakses pas violation terjadi), jadi bukan cuma "ada pelanggaran" tapi juga **konteks lengkapnya**.

```bash
sudo nano /var/www/html/csp-report.php
```

```php
<?php
$body = file_get_contents('php://input');
$data = json_decode($body, true);
$violation = $data['csp-report'] ?? [];

$log = [
    'timestamp'          => date('c'),
    'client_ip'          => $_SERVER['REMOTE_ADDR'] ?? '',
    'document_uri'       => $violation['document-uri'] ?? '',
    'referrer'           => $violation['referrer'] ?? '',
    'violated_directive' => $violation['violated-directive'] ?? '',
    'blocked_uri'        => $violation['blocked-uri'] ?? '',
    'source_file'        => $violation['source-file'] ?? '',
    'line_number'        => $violation['line-number'] ?? '',
    'script_sample'      => $violation['script-sample'] ?? '',
];

file_put_contents('/var/log/csp-reports.log', json_encode($log) . PHP_EOL, FILE_APPEND);
http_response_code(204);
```

`document_uri` di sini persis jawaban dari "apa yang sedang diakses" — isinya URL halaman guestbook (`http://10.10.10.10/vulnerabilities/xss_s/`) yang lagi dibuka korban pas payload-nya coba jalan. `client_ip` juga kepake buat identifikasi korban mana (misal Ubuntu Host) yang kena.

File log ini butuh permission writable buat `www-data`:

```bash
sudo touch /var/log/csp-reports.log
sudo chown www-data:www-data /var/log/csp-reports.log
```

### 4. Test manual endpoint

```bash
curl -i -X POST http://10.10.10.10/csp-report.php \
  -H "Content-Type: application/csp-report" \
  -d '{"csp-report":{"document-uri":"http://10.10.10.10/vulnerabilities/xss_s/","violated-directive":"script-src","blocked-uri":"inline"}}'
```

Harus balik `HTTP/1.1 204 No Content`, dan `cat /var/log/csp-reports.log` harus nunjukin baris JSON baru sesuai data test di atas.

### 5. Wazuh Agent baca `csp-reports.log`

Edit `/var/ossec/etc/ossec.conf` di Web-Server, tambahin `<localfile>`:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/csp-reports.log</location>
</localfile>
```

```bash
sudo systemctl restart wazuh-agent
```

`log_format json` dipilih karena file log-nya udah rapi satu JSON per baris — Wazuh bisa auto-extract semua field (`document_uri`, `blocked_uri`, dst) tanpa perlu custom decoder regex kayak yang dibutuhin buat log pfSense/Suricata.

### 6. Custom Wazuh rule — match `csp-reports.log`

Rule disimpan di [`Detection-Engineer/wazuh-rules/csp-report-rules.xml`](../Detection-Engineer/wazuh-rules/csp-report-rules.xml) — gak butuh custom decoder, karena `log_format json` bikin Wazuh auto-extract field lewat JSON decoder bawaan.

Copy ke `/var/ossec/etc/rules/` di Dell, test & restart:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager
```

Logic rule-nya:
- `100404` (`script-src-elem`, level `10`) — pelanggaran dari tag `<script>` beneran, selalu high-confidence karena browser bisa pinpoint `line_number`-nya
- `100405` (`script-src-attr`, level `3`) — pelanggaran dari inline event handler (`onclick=`, `onerror=`, dst), gak pernah ada `line_number` (limitasi browser, bukan indikator benign/malicious) — level rendah dulu, `script_sample` ditampilin di description buat triage manual
- `100406` (level `10`) — eskalasi dari `100405` kalau `script_sample` match pattern mencurigakan (`alert(`, `document.cookie`, dst), nutup celah attacker yang pake vektor attribute-based (bukan `<script>` tag)

> **Belum divalidasi `wazuh-logtest`** — Wazuh Manager (Dell) lagi gak available. Data sample yang udah dikumpulin manual dari `archives.log` (elem+`alert('nice')`, attr+3 fungsi DVWA legit, attr+`alert(1)`) dipakai buat verifikasi begitu Dell nyala lagi.

---

## Verifikasi

✅ **Pipeline Web-Server → Wazuh Manager confirmed** — direplay dari Ubuntu Host (`10.10.20.30`), dicek langsung di `archives.log` Dell:

```
2026 Jul 22 16:09:31 (web-server) any->/var/log/apache2/access.log 10.10.20.30 - - [22/Jul/2026:23:09:31 +0700] "GET /vulnerabilities/xss_s/x.com HTTP/1.1" 404 529 "http://10.10.10.10/vulnerabilities/xss_s/" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:149.0) Gecko/20100101 Firefox/149.0"
2026 Jul 22 16:09:31 (web-server) any->/var/log/csp-reports.log {"timestamp":"2026-07-22T16:09:31+00:00","client_ip":"10.10.20.30","document_uri":"http://10.10.10.10/vulnerabilities/xss_s/","referrer":"http://10.10.10.10/vulnerabilities/xss_r/","violated_directive":"script-src-attr","blocked_uri":"inline","source_file":"http://10.10.10.10/vulnerabilities/xss_s/","line_number":"","script_sample":"javascript:toggleTheme();"}
2026 Jul 22 16:09:31 (web-server) any->/var/log/csp-reports.log {"timestamp":"2026-07-22T16:09:31+00:00","client_ip":"10.10.20.30","document_uri":"http://10.10.10.10/vulnerabilities/xss_s/","referrer":"http://10.10.10.10/vulnerabilities/xss_r/","violated_directive":"script-src-attr","blocked_uri":"inline","source_file":"http://10.10.10.10/vulnerabilities/xss_s/","line_number":"","script_sample":"return validateGuestbookForm(this.form);"}
2026 Jul 22 16:09:31 (web-server) any->/var/log/csp-reports.log {"timestamp":"2026-07-22T16:09:31+00:00","client_ip":"10.10.20.30","document_uri":"http://10.10.10.10/vulnerabilities/xss_s/","referrer":"http://10.10.10.10/vulnerabilities/xss_r/","violated_directive":"script-src-attr","blocked_uri":"inline","source_file":"http://10.10.10.10/vulnerabilities/xss_s/","line_number":"","script_sample":"return confirmClearGuestbook();"}
2026 Jul 22 16:09:31 (web-server) any->/var/log/csp-reports.log {"timestamp":"2026-07-22T16:09:31+00:00","client_ip":"10.10.20.30","document_uri":"http://10.10.10.10/vulnerabilities/xss_s/","referrer":"http://10.10.10.10/vulnerabilities/xss_r/","violated_directive":"script-src-elem","blocked_uri":"inline","source_file":"http://10.10.10.10/vulnerabilities/xss_s/","line_number":94,"script_sample":"alert('nice')"}
```

Dua hal yang confirmed dari sample ini:
1. **`access.log`** kecatet normal buat request halaman guestbook-nya (`GET /vulnerabilities/xss_s/...`)
2. **`csp-reports.log`** ikut ke-forward Wazuh Agent → Wazuh Manager (Dell) — semua field (`document_uri`, `violated_directive`, `script_sample`, dst) nyampe utuh di `archives.log`, termasuk pembeda yang udah dibahas: 3x `script-src-attr` isinya fungsi DVWA legit (`toggleTheme`, `validateGuestbookForm`, `confirmClearGuestbook`) vs 1x `script-src-elem` isinya payload asli (`alert('nice')`, `line_number: 94`)

`archives.log` nyimpen **semua** log yang diterima Manager, regardless ke-match rule atau enggak — jadi ini baru bukti **pipeline collection-nya jalan**, belum bukti alert-nya ke-generate. Rule `csp-report-rules.xml` masih pending di-deploy & di-test (`wazuh-logtest`) di Dell — lihat catatan di [Step 6](#6-custom-wazuh-rule--match-csp-reportslog).

---

## Catatan

Beda dari `auditd`/Suricata yang nambah data source baru di layer endpoint/network, ini nambah data source dari layer **browser korban** — satu-satunya titik yang beneran "tau" ada payload aktif jalan pas momen replay, karena server-side gak pernah dapet sinyal apapun soal itu.
