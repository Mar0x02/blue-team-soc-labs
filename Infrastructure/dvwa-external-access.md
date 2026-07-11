# DVWA External Access — Expose ke Kali (External Attacker)

## Tujuan

Expose DVWA di Web-Server (`10.10.10.10`, LAN1) supaya bisa diakses **Kali Linux** (external attacker, di WAN/hotspot `192.168.43.x`) lewat NAT Port Forward di pfSense — simulasi realistis attacker yang cuma tau public-facing IP, bukan IP internal LAN1.

Sesuai catatan di [`dvwa-setup.md`](./dvwa-setup.md), exposure ini **sengaja gak dikonfigurasi waktu install DVWA** — baru dibuka pas mulai skenario attack spesifik, biar exposure-nya terkontrol.

---

## Prerequisites

- pfSense sudah running, WAN bridged ke hotspot — lihat [`pfsense-setup.md`](./pfsense-setup.md)
- Web-Server + DVWA sudah terinstall dan jalan di `10.10.10.10:80` — lihat [`dvwa-setup.md`](./dvwa-setup.md)
- Kali Linux sudah terkoneksi ke hotspot yang sama dengan WAN pfSense — lihat [`kali-setup.md`](./kali-setup.md)

---

## Step 1 — Buat NAT Port Forward di pfSense

1. Login Web GUI pfSense (`https://10.10.10.1`)
2. **Firewall → NAT → Port Forward** → **Add**
3. Isi:
   ```
   Interface           : WAN
   Protocol            : TCP
   Destination         : WAN address
   Destination port range : HTTP (80) to HTTP (80)
   Redirect target IP     : 10.10.10.10
   Redirect target port   : HTTP (80)
   Description         : Expose DVWA to Kali (external attacker) for attack scenario
   ```
4. Biarkan **"Filter rule association: Add associated filter rule"** tercentang (default) — pfSense otomatis bikin rule allow di **Firewall → Rules → WAN** yang match NAT ini
5. **Save → Apply Changes**

---

## Step 2 — Matikan "Block Private Networks" di WAN Interface

**Ini gotcha utama** — pfSense default nyalain opsi **Block private networks** dan **Block bogon networks** di WAN interface, didesain buat WAN yang beneran connect ke internet publik (nolak source address yang harusnya mustahil datang dari internet, kayak `192.168.x.x` / `10.x.x.x`).

Di lab ini, WAN pfSense **bridged ke hotspot** — yang notabene juga private range (`192.168.43.x`). Jadi source IP Kali sendiri ikut kena block duluan, **sebelum sempat dievaluasi NAT/rule di Step 1** — walaupun rule-nya udah bener 100%.

1. **Interfaces → WAN**
2. Scroll ke bagian bawah, cari:
   - **Block private networks and loopback addresses** → uncentang
   - **Block bogon networks** → uncentang
3. **Save → Apply Changes**

---

## Step 3 — Scope Firewall Rule ke Port 80 Saja

Cek rule hasil auto-generate dari Step 1:

1. **Firewall → Rules → WAN**
2. Buka rule yang barusan ke-generate (biasanya description-nya sama kayak NAT rule tadi)
3. Pastikan:
   ```
   Protocol      : TCP
   Destination     : 10.10.10.10
   Destination port : 80 (HTTP) — bukan "Any"
   ```

Ini penting biar exposure-nya cuma sebatas web app (DVWA) — kalau port dibiarkan "Any", service lain yang jalan di Web-Server (misal SSH port 22) ikut ke-expose ke Kali padahal skenario attack-nya cuma web.

---

## Verifikasi

### Dari Kali:

```bash
ping -c 4 192.168.43.99          # WAN pfSense → BOLEH gagal/block, ICMP emang gak di-pass, ini normal
curl -I http://192.168.43.99/    # → harus dapat response DVWA (redirect ke login.php atau 200)
```

Buka juga di browser: `http://<IP-WAN-pfSense>/` — harus muncul halaman login DVWA.

### Cek scope port (harus GAGAL selain port 80):

```bash
nc -zv 192.168.43.99 22   # SSH Web-Server → harus GAGAL/timeout kalau scoping Step 3 udah bener
```

### Dari pfSense (Status → System Logs → Firewall):

Request dari IP Kali ke port 80 harus muncul dengan action **pass** (hijau), bukan **block**.

---

## Troubleshooting

| Masalah | Kemungkinan Penyebab | Solusi |
|---------|----------------------|--------|
| Semua traffic dari Kali ke WAN pfSense keblock (termasuk yang udah ada NAT rule-nya) | **Block private networks** masih aktif di WAN — source Kali (`192.168.43.x`) ikut dianggap "private/spoofed" | Ulangi Step 2, uncentang **Block private networks** & **Block bogon networks** |
| `curl` connection refused (bukan timeout) | NAT rule salah target port, atau Apache di Web-Server gak jalan | Cek `sudo ss -tlnp \| grep :80` di Web-Server, pastikan Apache listen |
| NAT rule udah dibuat tapi gak ada rule otomatis muncul di **Firewall → Rules → WAN** | Opsi "Filter rule association" ke-uncheck pas bikin NAT rule | Edit NAT rule, centang lagi "Add associated filter rule", atau bikin manual rule pass di WAN |
| Port selain 80 (misal SSH) ternyata masih bisa diakses dari Kali | Rule WAN auto-generate masih pakai **Destination port: Any** | Ulangi Step 3, scope destination port ke `80` doang |
| IP WAN pfSense berubah-ubah tiap kali tes | Hotspot kasih IP dinamis via DHCP ke WAN pfSense | Cek IP terbaru di **Status → Interfaces → WAN** tiap mau tes ulang, jangan hardcode IP lama |

---

## Catatan Keamanan Lab

- **Exposure ini cuma sebatas jaringan WiFi hotspot** (`192.168.43.0/24`), bukan internet publik beneran — siapapun yang connect ke hotspot yang sama bisa akses DVWA, tapi gak ada exposure ke luar jaringan itu.
- Karena **Block private networks** dimatiin di WAN, pfSense jadi lebih longgar soal source address yang biasanya dicurigai spoofed — ini oke buat lab (WAN emang bukan internet publik asli), tapi kalau nanti WAN pfSense dipindah ke koneksi internet beneran, opsi ini **wajib dinyalain lagi**.
- Rule NAT + firewall ini **sengaja dibiarkan aktif selama skenario attack berjalan** (bukan cuma sekali tes) — matikan (disable, bukan hapus) rule-nya di **Firewall → NAT → Port Forward** kalau skenario attack udah selesai dan mau balik ke mode "DVWA cuma reachable dari LAN1/LAN2 doang".
- DVWA tetap **sengaja vulnerable** (security level Low/Medium sesuai kebutuhan lab) — target ideal buat simulasi SQL Injection, XSS, Command Injection, sampai file upload shell, yang nantinya dideteksi Wazuh dari sisi Web-Server.
