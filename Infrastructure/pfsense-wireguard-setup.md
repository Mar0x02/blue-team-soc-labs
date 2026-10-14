# pfSense — Remote Access VPN WireGuard (M1 → Lab)

## Tujuan

Akses **WebGUI pfSense** (dan network lab LAN1/LAN2) langsung dari **M1 (Mac)**, yang posisinya ada di **sisi WAN** pfSense (hotspot `192.168.43.0/24`).

Default-nya pfSense cuma buka WebGUI dari LAN (anti-lockout rule cuma ada di LAN1), dan WAN nge-block semua inbound. Daripada buka WebGUI langsung ke WAN, yang berarti ke-expose juga ke **Kali** yang ada di hotspot yang sama, jalurnya dibikin lewat **WireGuard remote access VPN**:

- Yang kebuka di WAN cuma **UDP 51820**. WireGuard gak ngebalas paket apa pun yang gak pakai key valid, jadi dari sisi Kali port itu kelihatan kayak tertutup.
- M1 dapat IP di tunnel subnet sendiri (`10.10.99.0/24`) dan bisa reach LAN1/LAN2 lewat pfSense.

WireGuard dipilih dibanding OpenVPN (harus urus CA/cert + client export) dan Tailscale (butuh akun dan control plane pihak ketiga), karena config-nya pendek dan konsepnya (key pair, cryptokey routing, firewall rule) kelihatan jelas buat dipelajari.

> Ini **remote access VPN klasik, bukan ZTNA**. Sekali tunnel naik, M1 dapat akses level network, bukan per-aplikasi. Prinsip zero trust yang diterapkan di sini cuma least privilege di firewall rule (Step 6).

---

## Prerequisites

- pfSense CE **≥ 2.6.0** (package WireGuard gak tersedia di 2.5.x) yang udah running dengan WAN dapat IP dari hotspot. Lihat [`pfsense-setup.md`](./pfsense-setup.md)
- pfSense bisa internetan lewat WAN (Package Manager ngambil package dari server Netgate)
- Akses WebGUI pfSense **dari dalam LAN** buat setup awal (browser VM LAN1/LAN2, atau PC host), karena dari M1 belum bisa sebelum VPN jadi
- M1: macOS 26.6.2 + app **WireGuard 1.0.16** (Mac App Store)

### Rencana alamat

| Item | Nilai |
|------|-------|
| Tunnel subnet | `10.10.99.0/24`, sengaja beda dari LAN1/LAN2 |
| pfSense (tunnel) | `10.10.99.1` |
| M1 (tunnel) | `10.10.99.2` |
| Listen port | UDP `51820` |
| Endpoint | IP WAN pfSense (`192.168.43.x`, DHCP hotspot) |

### Alokasi IP tunnel

WireGuard gak punya DHCP. IP client dipilih manual, ditulis di `Address` config client, dan **disahkan** di `Allowed IPs` peer di pfSense (keduanya harus sama). Satu device = satu key pair = satu IP `/32`.

| IP | Device | Akses (rule tab WireGuard) |
|----|--------|----------------------------|
| `10.10.99.1` | pfSense (`tun_wg0`) | — |
| `10.10.99.2` | M1 | `10.10.10.1` TCP 443 (WebGUI), `10.10.10.5` TCP 22 (SSH WAF), `10.10.10.10` TCP 22 (SSH Web-Server) |
| `10.10.99.3` | PC | `10.10.10.1` TCP 443 (WebGUI) |

---

## Step-by-Step

### 1. Install package WireGuard (pfSense)

Menu **VPN** default cuma berisi IPsec, L2TP, dan OpenVPN. WireGuard baru muncul setelah package di-install.

**System → Package Manager → Available Packages** → search `WireGuard` → **Install** → **Confirm** → tunggu `Success` → refresh. Menu **VPN → WireGuard** sekarang muncul.

### 2. Generate key pair di M1

App WireGuard → **+ → Add Empty Tunnel…** → Name: `pfsense-lab`.

Private key dan public key langsung ke-generate. **Copy Public key**-nya buat Step 4, terus **Save** dulu tanpa ngubah isi config.

> Yang dibagiin ke pfSense **cuma public key**. Private key gak pernah keluar dari Mac.

### 3. Bikin tunnel (pfSense)

**VPN → WireGuard → Tunnels → Add Tunnel**

| Field | Isi |
|-------|-----|
| Enabled | ✅ |
| Description | `wg-m1` |
| Listen Port | `51820` |
| Interface Keys | **Generate** |
| Interface Addresses | `10.10.99.1/24` |

**Copy Public Key** pfSense buat Step 7 → **Save Tunnel**.

Tunnel di sini adalah **interface virtual** (`tun_wg0`) yang nyimpen identitas pfSense sendiri: key pair, listen port, sama IP di jaringan tunnel.

### 4. Daftarin M1 sebagai peer (pfSense)

**VPN → WireGuard → Peers → Add Peer**

| Field | Isi |
|-------|-----|
| Enabled | ✅ |
| Tunnel | `tun_wg0 (wg-m1)` |
| Description | `M1` |
| Dynamic Endpoint | ✅ (M1 yang inisiasi koneksi) |
| Keep Alive | kosong |
| Public Key | public key **Mac** (Step 2) |
| Pre-shared Key | **kosong** (config Mac gak pakai PSK) |
| Allowed IPs | `10.10.99.2/32` |

**Save Peer** → **VPN → WireGuard → Settings** → ✅ **Enable WireGuard** → **Save** → **Apply Changes**.

Peer = daftar pihak di seberang yang boleh masuk. Satu tunnel bisa punya banyak peer (device baru tinggal **Add Peer** dengan key + IP `/32` baru).

### 5. Buka WireGuard di WAN (pfSense)

**5a. Matiin Block private networks**

**Interfaces → WAN** → bagian *Reserved Networks* → ❌ uncheck **Block private networks and loopback addresses** (Block bogon tetap ✅) → **Save** → **Apply Changes**.

M1 itu `192.168.43.x` (RFC1918). Kalau opsi ini nyala, paketnya di-drop sebelum sampai ke rule mana pun.

**5b. Allow UDP 51820**

**Firewall → Rules → WAN → Add (⬆)**

| Field | Isi |
|-------|-----|
| Action | Pass |
| Address Family | IPv4 |
| Protocol | **UDP** |
| Source | Network `192.168.43.0/24` (IP M1 berubah-ubah dari DHCP) |
| Destination | **WAN address**, port `51820` |
| Description | `Allow WireGuard from hotspot` |

**Save** → **Apply Changes**.

### 6. Rule di dalam tunnel (pfSense) — least privilege

Semua traffic dari client VPN masuk lewat interface **WireGuard**, jadi tab **Firewall → Rules → WireGuard** yang nentuin client boleh ke mana. Yang gak di-allow di tab ini otomatis kena **default deny**.

Rule-nya dibikin **per client (single host), per tujuan, per port**. Bukan `10.10.99.0/24 → any`, karena kalau pakai yang itu, client yang udah masuk VPN bisa ke seluruh LAN1/LAN2 (termasuk WIN AD: SMB, LDAP, Kerberos, RDP), dan peer baru di subnet itu otomatis dapat akses yang sama.

**Firewall → Rules → WireGuard → Add**

| Field | Isi |
|-------|-----|
| Action | Pass |
| Protocol | **TCP** |
| Source | **Single host or alias** → `10.10.99.2` |
| Source Port | **any** (port acak/ephemeral dari client) |
| Destination | **Single host or alias** → `10.10.10.1` |
| Destination Port | **HTTPS (443)** |
| Description | `M1 → pfSense WebGUI` |

**Save** → **Apply Changes**.

- Kalau di tab ini masih ada rule longgar (`10.10.99.0/24 → *`), rule itu harus **dihapus atau di-disable**. Kalau dibiarin, aksesnya tetap kebuka karena *first match wins*. Urutannya: Save rule baru dulu, **baru** disable yang lama, biar koneksi WebGUI lewat VPN gak putus.
- Alternatif destination **This Firewall (self)** port 443 ngizinin WebGUI lewat semua IP pfSense (`10.10.10.1`, `10.10.20.1`, `10.10.99.1`, WAN). Single host `10.10.10.1` lebih sempit.
- **Destination Port Range** punya dua dropdown (**From** / **To**), dan **dua-duanya** harus diisi (misal `HTTPS (443)` – `HTTPS (443)`). Kalau salah satunya masih `any`, rule tetap kebuka ke **semua port** (kolom Port di daftar rule tampil `*`).
- Port 443 = port default WebGUI. Cek di **System → Advanced → Admin Access → TCP port** kalau pernah diganti.

### 7. Lengkapin config tunnel di M1

App WireGuard → `pfsense-lab` → **Edit**. Baris `PrivateKey` dibiarin, tambahin sisanya:

```ini
[Interface]
PrivateKey = <auto-generated, jangan diubah>
Address = 10.10.99.2/32

[Peer]
PublicKey = <public key tunnel pfSense>
Endpoint = <IP-WAN-pfSense>:51820
AllowedIPs = 10.10.99.0/24, 10.10.10.0/24, 10.10.20.0/24
PersistentKeepalive = 25
```

`AllowedIPs` di sisi Mac artinya **tujuan mana yang dilewatin tunnel** (split tunnel). Internet Mac tetap lewat hotspot. Di sisi pfSense, `Allowed IPs` peer artinya **source IP yang diterima dari peer itu**. Pasangan public key ↔ IP ini yang disebut *cryptokey routing*.

> ⚠️ **Public key pfSense jangan diketik manual.** Ambil dari shell pfSense pakai `wg show tun_wg0 public-key` atau dari halaman Tunnel, terus pindahin ke Mac lewat copy-paste (chat/email/notes ke diri sendiri). Public key aman disebar. Typo satu karakter aja bikin handshake gagal total (lihat Troubleshooting).

**Save** → **Activate**.

---

## Verifikasi

**1. Route tunnel ke-install di Mac**

```bash
netstat -rn -f inet | grep -E "10\.10\.|utun"
```

`10.10.10/24`, `10.10.20/24`, `10.10.99/24` harus lewat `utunX`.

**2. Handshake jalan**

```bash
sudo tcpdump -ni en0 host <IP-WAN-pfSense> and udp port 51820
```

```
192.168.43.<mac>.xxxxx > 192.168.43.<pfsense>.51820: UDP, length 148   ← handshake initiation
192.168.43.<pfsense>.51820 > 192.168.43.<mac>.xxxxx: UDP, length 92    ← handshake response
```

Di pfSense: **Status → WireGuard** → peer `M1` ada **Latest Handshake** (bukan `never`), dan `wg show` nampilin baris `endpoint: 192.168.43.<mac>:xxxxx`.

**3. Akses dari Mac**

```bash
ping -c 3 10.10.99.1
ping -c 3 10.10.10.1
```

Browser Mac → **`https://10.10.10.1`** → dashboard pfSense kebuka.

**4. Least privilege jalan (setelah Step 6)**

```bash
curl -kI https://10.10.10.1            # harus bisa (HTTP 200/302)
curl -kI -m 5 https://10.10.20.1       # harus timeout (IP pfSense lain, gak di-allow)
nc -vz -G 3 10.10.10.10 22             # harus bisa (SSH Web-Server di-allow)
nc -vz -G 3 10.10.10.10 80             # harus gagal (HTTP gak di-allow)
nc -vz -G 3 10.10.10.1 22              # harus gagal (SSH pfSense gak di-allow)
```

Di daftar rule, kolom Port (destination) tiap rule harus nunjukin port spesifik (`443 (HTTPS)` / `22 (SSH)`), bukan `*`.

Percobaan yang di-block muncul di **Status → System Logs → Firewall** sebagai block dari `10.10.99.2` (Default deny rule).

✅ Confirmed live 2026-10-14: handshake sukses, dashboard pfSense bisa diakses dari M1 lewat tunnel, dan setelah rule dibatasi per host + port (tabel Alokasi IP tunnel) akses yang di-allow jalan sementara port lain ke host yang sama gagal.

---

## Troubleshooting

Urutan cek yang dipakai waktu setup ini (handshake `never`), dari sisi Mac sampai ke modul WireGuard pfSense:

| Langkah | Command | Kalau gagal |
|---------|---------|-------------|
| Paket keluar dari Mac? | `sudo tcpdump -ni en0 udp port 51820` | Tunnel belum benar-benar up. Deactivate → Activate, cek route (Verifikasi 1) |
| Route masuk tunnel? | `route -n get 10.10.10.1` | Kalau lewat `en0`/gateway hotspot, route `AllowedIPs` belum ke-install |
| Paket sampai pfSense? | Shell pfSense: `tcpdump -ni em0 udp port 51820` | Endpoint IP salah / adapter WAN belum bridged |
| Lolos firewall? | **Status → System Logs → Firewall** + `pfctl -ss \| grep 51820` | Ada block → cek 5a / 5b |
| Kenapa gak dibalas? | `ifconfig tun_wg0 debug` → `dmesg \| grep -i wg` | Baca pesan error (tabel di bawah). Matiin lagi: `ifconfig tun_wg0 -debug` |

### Cara baca hasil

| Temuan | Artinya |
|--------|---------|
| `pfctl -ss` state `NO_TRAFFIC:SINGLE` | Paket lolos firewall tapi **gak ada balasan** dari pfSense, jadi masalahnya di WireGuard, bukan network |
| `Invalid initiation MAC` | `mac1` dihitung pakai public key responder, jadi **`[Peer] PublicKey` di Mac ≠ public key tunnel pfSense**. Ini root cause di setup ini (typo karena diketik manual) |
| `Invalid handshake initiation` | Public key **Mac** di Peer pfSense salah, atau PSK cuma diisi di satu sisi |
| `wg show` peer gak punya baris `endpoint:` | pfSense belum pernah nerima handshake valid dari peer itu |

### Gotcha lain yang ketemu

| Gejala | Penjelasan |
|--------|------------|
| `arp -n <IP-WAN-pfSense>` di Mac nunjukin MAC beda dari MAC WAN pfSense | Normal. WAN pfSense di-bridge lewat WiFi, dan bridging WiFi pakai MAC address translation (frame VM keluar pakai MAC WiFi PC host) |
| tcpdump di Mac nunjukin traffic UDP 51820 ke IP publik | Bukan dari tunnel ini. Cek `sudo lsof -nP -iUDP:51820`. Di M1 itu daemon **NetBird** 0.60.7 (VPN mesh berbasis WireGuard, jalan sebagai service `root` dari boot walaupun gak di-connect). Gak bentrok, karena app WireGuard pakai source port random |
| VPN lain gak kelihatan di `scutil --nc list` | Daemon kayak NetBird bikin `utun` sendiri, gak lewat Network Extension macOS |
| Paket `:5353` / `:57621` di capture/firewall log | mDNS (Bonjour) dan Spotify LAN discovery, cuma noise broadcast hotspot |
| Tunnel tiba-tiba gak connect besoknya | IP WAN pfSense dari DHCP hotspot berubah, jadi update `Endpoint` di Mac |
| Ping ke VM Windows gagal tapi WebGUI bisa | Windows Firewall nge-block ICMP dari subnet lain, bukan masalah VPN |
