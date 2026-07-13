# pfSense — Syslog Forwarding ke Wazuh Manager

## Tujuan

Kirim log pfSense (`10.10.10.1` LAN1/`10.10.20.1` LAN2, WAN di hotspot) ke **Wazuh Manager** di Dell lewat **syslog forwarding** — pfSense itu FreeBSD appliance, gak bisa dipasangin Wazuh Agent biasa kayak endpoint lain, jadi mekanismenya beda: pfSense jadi syslog client, Wazuh Manager jadi syslog server (UDP 514).

Ini endpoint terakhir dari monitoring infrastructure, dan paling ribet — defaultnya Wazuh gak bisa langsung parse format log pfSense dengan benar, butuh custom decoder + rule.

---

## Prerequisites

- pfSense running dengan LAN1/LAN2 aktif — lihat [`pfsense-setup.md`](./pfsense-setup.md)
- Wazuh Manager di Dell running — lihat [`wazuh-setup.md`](./wazuh-setup.md)
- Akses SSH ke Dell (install `openssh-server` kalau belum ada) — jauh lebih gampang buat command panjang/berulang dibanding console langsung

---

## Step 1 — Aktifkan Remote Syslog di pfSense

**Status → System Logs → Settings** → **Remote Logging Options**:

```
Send log messages to remote syslog server(s): ✓ (centang)
Remote log servers                          : <IP-Dell>:514
Source Address                               : Any
Firewall Events                              : ✓ (wajib, ini yang generate log filterlog)
```

> **Gotcha — Source Address:** Defaultnya kepilih **WAN** (kepilih otomatis karena WAN interface-nya paling "utama"). Ini bikin syslog **gak jalan sama sekali**, padahal config lain semua bener dan `tcpdump` di Dell kosong total. Ganti ke **Any**, langsung jalan. Kemungkinan soal binding — WAN pfSense di lab ini bridged ke hotspot (bukan WAN normal), jadi behavior binding-nya beda dari WAN biasa.

Format syslog (**BSD (RFC 3164)** vs **Syslog (RFC 5424)**) — **gak ngaruh**, dua-duanya sama-sama butuh custom decoder (lihat Step 3). Pakai BSD aja (default, lebih compact).

---

## Step 2 — Aktifkan Wazuh Manager Nerima Syslog

Default Wazuh Manager cuma listen buat agent (port 1514), belum listen syslog. Edit `/var/ossec/etc/ossec.conf` di Dell:

```bash
sudo nano /var/ossec/etc/ossec.conf
```

Tambahin (sejajar sama block lain, di dalam `<ossec_config>`, posisi bebas):

```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>udp</protocol>
  <allowed-ips>192.168.43.99</allowed-ips>
</remote>
```

> **Kenapa `allowed-ips` di-scope ke IP pfSense doang (bukan `/24`):** Syslog UDP gak ada autentikasi — kalau dibuka ke seluruh subnet hotspot, device lain (termasuk Kali, si attacker) bisa inject log palsu yang diproses Wazuh seolah dari pfSense. Trade-off-nya: IP WAN pfSense dinamis (DHCP hotspot), jadi field ini perlu di-update manual kalau IP-nya berubah.

Restart manager:

```bash
sudo systemctl restart wazuh-manager
```

---

## Step 3 — Custom Decoder + Rule

Wazuh punya ruleset default buat pfSense (`/var/ossec/ruleset/decoders/0455-pfsense_decoders.xml`), tapi **gak match** — pfSense ngirim syslog tanpa field hostname (`Jul 12 01:04:25 filterlog[64366]: ...` bukan `Jul 12 01:04:25 pfSense filterlog[64366]: ...`), jadi predecoder Wazuh salah nangkep `filterlog[64366]:` sebagai hostname, bukan program_name. Decoder default yang nyari `program_name == filterlog` gak pernah match. Sudah dicoba juga format RFC 5424 (Step 1), sama-sama gagal karena predecoder Wazuh gak otomatis parse header RFC 5424.

Solusinya: custom decoder yang match langsung ke pola raw text-nya, gak bergantung ke auto-extraction hostname/program_name.

```bash
sudo nano /var/ossec/etc/decoders/local_decoder.xml
```

```xml
<decoder name="pfsense-filterlog">
  <prematch>filterlog</prematch>
  <regex offset="after_prematch">^\S* \S*,\S*,\S*,\S*,(\S*),(\S*),(\S*),(\S*),\S*,\S*,\S*,\S*,\S*,\S*,\S*,\S*,(\S*),\S*,(\S*),(\S*),(\S*),(\S*),</regex>
  <order>interface,reason,action,direction,protocol,srcip,dstip,srcport,dstport</order>
</decoder>
```

```bash
sudo nano /var/ossec/etc/rules/local_rules.xml
```

```xml
<!-- Local rules -->
<!-- Modify it at your will. -->

<group name="pfsense,firewall,">
  <rule id="100100" level="0">
    <decoded_as>pfsense-filterlog</decoded_as>
    <description>pfSense: firewall log event</description>
  </rule>

  <rule id="100101" level="5">
    <if_sid>100100</if_sid>
    <action>block</action>
    <description>pfSense: traffic blocked - $(srcip):$(srcport) -> $(dstip):$(dstport) [$(protocol)]</description>
  </rule>

  <rule id="100102" level="3">
    <if_sid>100100</if_sid>
    <action>pass</action>
    <description>pfSense: traffic passed - $(srcip):$(srcport) -> $(dstip):$(dstport) [$(protocol)]</description>
  </rule>
</group>
```

> **Gotcha regex — Wazuh pakai OSRegex, bukan PCRE penuh:**
> - **Gak support kuantifier `+`** (misal `\d+`) — cuma support `*`. Pakai `\d*` atau lebih aman lagi pakai `\S*` polos.
> - **Hindari literal bracket `[` `]`** — OSRegex nganggep `[` sebagai awal character class, dan kalau gak ketutup bener bikin pattern gagal match diam-diam (gak error di config test, tapi gak pernah match). Solusinya, telen aja bagian yang ada bracket-nya pakai `\S*` (contoh: `[64366]:` ke-handle sebagai satu token non-whitespace, gak perlu match bracket secara eksplisit).
> - **Field "static/reserved"** kayak `action`, `srcip`, `dstip`, `srcport`, `dstport`, `protocol` — kalau field ini didefinisikan di `<order>` decoder, di rule harus dipanggil pakai tag khusus (`<action>block</action>`), **bukan** `<field name="action">block</field>` (itu cuma buat custom field yang gak ada di daftar reserved Wazuh) — kalau salah, `wazuh-analysisd -t` error "Field 'x' is static".

Test config, restart, verifikasi pakai `wazuh-logtest` sebelum nunggu traffic asli:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager

# test manual pakai raw log contoh (harus di 1 baris, jangan lewat interactive paste biar gak ke-split)
echo 'Jul 12 01:04:25 filterlog[64366]: 4,,,1000000103,em0,match,block,in,4,0x0,,64,46568,0,none,17,udp,72,192.168.43.193,192.168.43.255,57621,57621,52' > /tmp/test-bsd.log
cat /tmp/test-bsd.log | sudo /var/ossec/bin/wazuh-logtest
```

Harus keluar semua field ke-extract dan `**Alert to be generated.**` di akhir output.

---

## Verifikasi

### 1. Paket beneran nyampe (network level, gak peduli parsing):

```bash
sudo tcpdump -i any udp port 514 -n
```

### 2. Raw log ter-archive:

```bash
sudo tail -f /var/ossec/logs/archives/archives.log
```

### 3. Alert ter-generate:

```bash
sudo tail -f /var/ossec/logs/alerts/alerts.log
```

### 4. Dari Wazuh Dashboard (Discover), pakai DQL:

```
rule.id: "100101" or rule.id: "100102"
```

Buat generate traffic test yang pasti kena log block (isolasi LAN2→LAN1), dari VM LAN2:
```bash
ping 10.10.10.10
```

---

## Troubleshooting

| Masalah | Kemungkinan Penyebab | Solusi |
|---------|----------------------|--------|
| `tcpdump udp port 514` kosong total, padahal setting pfSense udah bener | **Source Address** di Remote Logging Options ke-set ke `WAN` | Ganti ke **Any** — lihat gotcha di Step 1 |
| Setting pfSense udah bener, IP cocok, tapi tetep gak ada traffic masuk | syslogd pfSense "nyangkut" state lama (biasa kejadian abis gonta-ganti format BSD/RFC5424) | Uncentang "Send log messages..." → Save → centang lagi → Save (paksa reload) |
| `wazuh-analysisd -t` error `Syntax error on regex` | Regex pakai fitur PCRE yang gak didukung OSRegex (`+`, dll) | Ganti ke `*`, hindari kuantifier `+` |
| `wazuh-analysisd -t` error `Field 'x' is static` | Field reserved (action, srcip, dll) dipanggil pakai `<field name="x">` | Ganti ke tag dedicated (`<action>`, `<srcip>`, dll) |
| Decoder match (`name: 'pfsense-filterlog'`) tapi rule cuma level 0, field kosong | Regex fields belum nyesuain sama sisa text setelah prematch (masih ada `[PID]: ` yang belum ke-skip) | Tambahin `\S* ` di awal regex fields buat "nelen" bagian `[PID]:` sebelum CSV mulai |
| `wazuh-logtest` di-paste manual hasilnya kepotong/ke-split jadi 2 log | Line panjang ke-wrap pas paste ke terminal interactive | Tulis raw log ke file dulu (`cat > file << EOF`), cek `wc -l` harus `1`, baru `cat file \| wazuh-logtest` |
| Raw log yang ditest ternyata masih include prefix `<timestamp> Wazuh->192.168.43.99` | Itu format internal `archives.log` (metadata Wazuh), bukan bagian syslog message asli | Strip prefix itu manual, cuma pakai bagian setelah `Wazuh->IP` |

---

## Catatan

Custom decoder (`local_decoder.xml`) dan rule (`local_rules.xml`) ini juga disalin ke `Detection-Engineer/wazuh-rules/` di repo, biar ke-track sebagai detection engineering asset (bukan cuma nempel di server Dell doang, yang gak ke-backup/ke-version-control).

Dengan ini, semua infrastructure monitoring lab udah lengkap: 5 endpoint agent (Ubuntu Host, Win7, WinXP, WIN AD, Web-Server) + pfSense syslog + Sysmon di WIN AD.
