# pfSense — Suricata (NIDS)

## Tujuan

Pasang **Suricata** di pfSense sebagai **NIDS** (Network Intrusion Detection System), nutup blind spot yang ketemu di lab [Command Injection](../Labs/web-server-attack/command-injection/README.md): request **POST** dan **reverse shell berbasis LOLBin** (`sh`, `nc`, `mkfifo`) gak ninggalin jejak sama sekali di `access.log` maupun Wazuh Agent (log-based + FIM). Suricata jalan di layer network, independen dari limitasi logging tiap aplikasi — jadi tetep bisa lihat traffic-nya walaupun aplikasi/OS di endpoint gak nyatet apa-apa.

---

## Kenapa Suricata (bukan Snort)

Dua-duanya sama-sama NIDS engine populer dan sama-sama tersedia sebagai package resmi di pfSense, tapi dipilih **Suricata**:

1. **Multi-threaded vs single-threaded** — Suricata didesain multi-threaded dari awal, bisa manfaatin banyak core CPU sekaligus. Snort (versi 2.x yang jadi basis package pfSense) secara arsitektur single-threaded per proses. Ini penting karena pfSense di lab ini nanggung kerjaan firewall + routing + sekarang NIDS di device yang sama — resource jadi lebih efisien.
2. **Tetep kompatibel sama ruleset Snort** — Suricata bisa baca dan jalanin **rule format Snort/Emerging Threats (ET)** apa adanya. Jadi gak ada yang hilang dari pindah ke Suricata — semua komunitas rule yang biasa dipakai buat Snort tetep bisa dipakai di sini.
3. **Snort kerasa lebih monoton** — dari sisi pengembangan, Snort 2.x udah lama gak banyak berubah secara arsitektur (Snort 3 ada, tapi adopsi & tooling di ekosistem, termasuk package pfSense, belum semasif Snort 2). Suricata jauh lebih aktif dikembangin (OISF), fitur-nya lebih lengkap keluar dari sekadar signature-based alert: ada TLS/JA3 fingerprinting, file extraction, protocol logging (HTTP, DNS, TLS) bawaan.
4. **Output `eve.json`** — ini yang paling krusial buat lab ini. Suricata native ngeluarin log dalam format **JSON terstruktur** (`eve.json`), jauh lebih gampang di-parse Wazuh dibanding format Snort (`unified2`/syslog polos) yang butuh decoder custom lebih ribet — mirip kayak masalah custom decoder yang udah ditemuin di [`pfsense-wazuh-syslog.md`](./pfsense-wazuh-syslog.md), gak mau nambah lagi kerumitan serupa di sisi NIDS.

**Kesimpulan:** Suricata dipilih karena performanya lebih baik di device yang udah multi-tasking (firewall + NIDS), tetep dapet manfaat ruleset komunitas Snort/ET, dan integrasinya ke Wazuh jauh lebih mulus lewat `eve.json` — tanpa kehilangan apapun dibanding pakai Snort langsung.

---

## Prerequisites

- pfSense running dengan LAN1/LAN2 aktif — lihat [`pfsense-setup.md`](./pfsense-setup.md)
- Wazuh Manager di Dell running — lihat [`wazuh-setup.md`](./wazuh-setup.md)
- Referensi integrasi syslog pfSense→Wazuh yang udah ada — lihat [`pfsense-wazuh-syslog.md`](./pfsense-wazuh-syslog.md) buat pola forwarding & gotcha decoder yang mirip

---

## Step-by-Step

### 1. Install package Suricata

**System → Package Manager → Available Packages** → cari `suricata` → **Install**

### 2. Assign ke interface LAN1

**Services → Suricata → Interfaces** → **Add**:

```
Interface : LAN1 (10.10.10.x — tempat Web-Server berada)
Enable    : ✓ (centang, tapi jangan Start dulu sebelum rules ke-download di Step 3)
```

> LAN1 dipilih (bukan WAN atau LAN2) karena ini interface tempat traffic ke/dari Web-Server lewat — target monitoring utama sesuai temuan lab Command Injection.

### 3. Download & enable ruleset

**Suricata → Updates** → centang source rule **Emerging Threats Open (ET Open) Ruleset** — gratis, gak perlu registrasi/Oinkcode, community-maintained, format udah kompatibel karena Suricata baca rule Snort/ET apa adanya → **Update**

> Skip **Snort VRT/Subscriber Ruleset** (butuh Oinkcode berbayar/daftar akun Snort.org) dan feed IOC kayak Feodo Tracker/abuse.ch (buat deteksi malware C2 known-IP, di luar scope lab ini).

Habis itu masuk **Interfaces → LAN1 → Categories**, centang kategori yang relevan buat lab ini:
```
emerging-web_server.rules
emerging-web_specific_apps.rules
emerging-exploit.rules
emerging-shellcode.rules
emerging-attack_response.rules
custom.rules
```

`emerging-attack_response.rules` paling krusial buat skenario reverse shell — kategori ini isinya signature buat "tanda-tanda command berhasil dieksekusi di korban" (misal output `uid=` dari `id`, banner shell), yang paling relevan nangkep traffic shell interaktif pas ngirim balik output command ke Kali.

`custom.rules` beda dari 5 kategori lain — ini bukan bagian ET Open, tapi container kosong buat rule yang ditulis sendiri. Rule ET Open sifatnya generic, kemungkinan gak match persis sama payload spesifik lab ini (`mkfifo`+`nc` reverse shell, command injection lewat form DVWA). Centang dulu kategorinya biar aktif — isi rule-nya nyusul, mirip pola custom Wazuh rule yang udah dibuat buat SQLi (`Detection-Engineer/wazuh-rules/sql_injection_rules.xml`), nanti disimpen di `Detection-Engineer/` juga.

### 4. Pastiin mode IDS, bukan IPS

Di **Interfaces → LAN1 → General Settings**, biarin **Block Offenders / IPS Mode** dalam keadaan **unchecked** — konsisten sama filosofi lab "deteksi dulu, bukan blocking". Suricata cuma nge-alert, gak drop paket.

### 5. Start Suricata di interface LAN1

Balik ke **Suricata → Interfaces**, klik tombol **Start** (▶) di baris LAN1.

### 6. Forward alert lewat syslog forwarding yang udah ada

pfSense gak bisa dipasangin Wazuh Agent (FreeBSD appliance — sama kayak alasan di [`pfsense-wazuh-syslog.md`](./pfsense-wazuh-syslog.md)), dan pengiriman `eve.json` mentah keluar dari pfSense butuh tooling tambahan yang gak trivial di appliance ini. Jalur paling pragmatis: manfaatin **syslog forwarding pfSense→Wazuh Manager yang udah aktif**.

Di **Interfaces → LAN1 → Alert Settings**, cari opsi **Send Alert to System Log** (atau **Send Alert Data to Syslog**, nama persisnya bisa beda tergantung versi package) → centang. Alert Suricata (turunan dari `eve.json`, tapi versi ringkas satu baris) bakal numpang lewat mekanisme syslog pfSense yang sama, otomatis ke-forward ke Dell tanpa setup baru.

Alert Suricata dikirim dengan **syslog facility `LOCAL1`**, bukan facility yang eksplisit ke-cover di kategori checkbox manapun di **Remote Logging Options** (`Status → System Logs → Settings`). Sempet dicoba centang **"Everything"** buat mastiin gak ke-block — berhasil, tapi ternyata bikin volume log ke Dell jadi kebanjiran noise gak relevan.

✅ **Confirmed:** kategori awal (**System Events**, **Firewall Events**, **DNS Events**, **DHCP Events** — tanpa "Everything") **udah cukup**, `LOCAL1` tetep ke-forward. Dites di 2 waktu berbeda (malam & pagi keesokan harinya, beda ~10 jam) dan konsisten nyampe. Kemungkinan besar `LOCAL1` ke-cover sama kategori **"System Events"**. Gak perlu "Everything" — balik ke setelan awal buat ngurangin noise, forwarding Suricata tetep jalan.

### 7. Cek format raw log sebelum bikin decoder

**Jangan langsung nulis decoder/rule Wazuh dari asumsi** — kayak yang kejadian di `pfsense-wazuh-syslog.md` (format raw pfSense ternyata beda dari ekspektasi), cek dulu bentuk asli log Suricata yang nyampe ke Dell:

```bash
sudo tail -f /var/ossec/logs/archives/archives.log
```

Trigger 1 alert sample (traffic apapun, bahkan noise kayak `SURICATA STREAM excessive retransmissions` cukup buat dapetin sample format), lihat bentuk raw line-nya. Format yang ketemu (fast.log style klasik Suricata/Snort):

```
suricata[23679]: [1:2210054:1] SURICATA STREAM excessive retransmissions [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 91.189.91.81:80 -> 10.10.10.10:53608
```

### 8. Custom decoder + rule

Decoder-nya disimpen di [`Detection-Engineer/wazuh-rules/suricata-decoder.xml`](../Detection-Engineer/wazuh-rules/suricata-decoder.xml):

```xml
<decoder name="suricata-alert">
  <prematch>suricata</prematch>
  <regex offset="after_prematch" type="pcre2">\[\d+\]:\s+\[(\d+:\d+:\d+)\]\s+(.+?)\s+\[Classification:\s+([^\]]+)\]\s+\[Priority:\s+(\d+)\]\s+\{([a-zA-Z]+)\}\s+([\d\.]+):(\d+)\s+->\s+([\d\.]+):(\d+)</regex>
  <order>suricata.sid,suricata.message,suricata.classification,suricata.priority,protocol,srcip,srcport,dstip,dstport</order>
</decoder>
```

Rule dasar + contoh child rule spesifik ada di [`Detection-Engineer/wazuh-rules/suricata-rules.xml`](../Detection-Engineer/wazuh-rules/suricata-rules.xml) — rule dasar (`100400`, level 3) generate alert buat **semua** alert Suricata, child rule (`100401`) contoh nge-filter SID spesifik (misal SID custom `1000001` dari `custom.rules` yang dibahas di section sebelumnya).

> **Gotcha regex PCRE2 — bikin frustasi lumayan lama, dicatet biar gak keulang:**
> - **`<prematch>` itu wajib** buat root decoder Wazuh (gak punya `<parent>`) — walaupun mau ngandelin regex PCRE2 sepenuhnya buat matching, `<prematch>` tetep harus ada, kalau enggak `wazuh-analysisd -t` langsung error `No 'prematch' found in decoder`.
> - **Jangan pakai anchor `^` bareng `offset="after_prematch"` + `type="pcre2"`.** Di PCRE2 asli, `offset` cuma nge-set "mulai cari regex dari posisi mana", tapi `^` tetep anchor ke **posisi 0 dari string ASLI** (bukan posisi abis-offset) kecuali pakai mode khusus. Kombinasi keduanya bikin regex gak pernah match sama sekali — decoder ke-detect (karena prematch berhasil) tapi **field-nya kosong semua**, tanpa error apapun (silent fail). Solusinya: buang `^`, biarin PCRE2 nyari pattern-nya sendiri dari titik offset ke depan.
> - **Jangan ulangin teks yang udah "dimakan" `<prematch>` di dalam `<regex>`.** Kalau `<prematch>suricata</prematch>`, regex-nya harusnya mulai dari SETELAH teks "suricata" (misal `\[\d+\]:...`), bukan include ulang `suricata\[\d+\]:...` — walaupun teksnya ada secara visual di raw log, bagian itu udah "dikonsumsi" prematch dan gak ada lagi di window teks yang di-scan regex.
> - **`<order>` gak boleh ada spasi setelah koma** (`a,b,c` bukan `a, b, c`) — beda sama gaya penulisan XML biasa yang lebih toleran, ini bisa jadi sumber silent-fail juga (walau belum 100% confirmed jadi akar masalah tunggal, tetep dibenerin buat konsistensi sama decoder pfSense yang udah kebukti kerja).
> - **Validasi regex di luar Wazuh dulu** (regex101.com, flavor PCRE2) sebelum masuk ke `wazuh-logtest` — jauh lebih cepet nemuin bug pattern-nya sendiri lewat visual match highlighting, ketimbang bolak-balik edit-restart-test di Wazuh buat isolasi apakah masalahnya di pattern atau di cara Wazuh ngejalanin PCRE2-nya.

---

## Verifikasi

✅ **Decoder & rule dasar confirmed** — divalidasi pakai `wazuh-logtest` dengan sample raw log Suricata beneran (`SURICATA STREAM excessive retransmissions`), semua field ke-extract dengan benar (`suricata.sid`, `suricata.message`, `suricata.classification`, `suricata.priority`, `protocol`, `srcip`, `srcport`, `dstip`, `dstport`), rule `100400` fire dengan alert level 3.

✅ **End-to-end confirmed** — payload command injection asli (`;id`) di-replay dari Kali, custom rule `custom.rules` (SID `1000003`, "Detect Command Injection separators in POST Body") ke-trigger Suricata di LAN1, alert-nya nyampe ke Wazuh Dashboard lewat decoder+rule `100400` yang sama. Muncul BARENGAN sama alert auditd (`100300`) buat request yang sama — network layer (Suricata) dan endpoint layer (auditd) dua-duanya independen ke-detect. Detail lengkap + evidence GIF ada di section ["Verifikasi Remediasi"](../Labs/web-server-attack/command-injection/README.md#verifikasi-remediasi--blind-spot-sekarang-ketutup) di writeup Command Injection.
