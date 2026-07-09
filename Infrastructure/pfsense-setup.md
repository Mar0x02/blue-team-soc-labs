# pfSense Setup — Firewall & Gateway Lab

## Tujuan

Menginstall dan mengkonfigurasi pfSense sebagai firewall, gateway, dan router untuk memisahkan zona jaringan lab:
- **LAN1 (Server Zone):** `10.10.10.0/24` — Web Server + Windows AD
- **LAN2 (Host Zone):** `10.10.20.0/24` — Windows PC + Kali Linux
- **WAN:** `192.168.43.x` — Hotspot (akses internet)

---

## Prerequisites

- PC sudah terinstall **VMware Workstation Pro** (gratis untuk personal use, download di [broadcom.com](https://support.broadcom.com/group/ecx/productdownloads?subfamily=VMware+Workstation+Pro))
- ISO pfSense sudah didownload dari [netgate.com/downloads](https://www.netgate.com/downloads) — pilih versi **AMD64, DVD Image (ISO)**
- Spesifikasi VM minimal: 1 CPU, 1 GB RAM, 10 GB storage, **3 NIC**

---

## Step 1 — Buat VM di VMware Workstation Pro

### 1.1 Buat VM baru

1. Buka VMware Workstation Pro → **File → New Virtual Machine**
2. Pilih **Custom (advanced)** → Next
3. **Hardware compatibility:** biarkan default (versi terbaru) → Next
4. **Installer disc image file (ISO):** pilih ISO pfSense yang sudah didownload → Next
5. **Guest OS:** pilih **Other** → **FreeBSD 64-bit** → Next
6. **VM Name:** `pfSense` → tentukan lokasi penyimpanan → Next
7. **Processors:** `1 processor, 1 core` → Next
8. **Memory:** `1024 MB` → Next
9. **Network:** pilih **Use bridged networking** (untuk WAN dulu, NIC tambahan dikonfigurasi setelah VM dibuat) → Next
10. **I/O Controller:** LSI Logic → Next
11. **Disk type:** SCSI → Next
12. **Disk:** Create a new virtual disk → `10 GB`, Store as single file → Next
13. **Finish**

### 1.2 Setup VMnet di Virtual Network Editor (wajib sebelum assign NIC)

VMware default hanya punya **VMnet1** (Host-only) dan **VMnet8** (NAT). VMnet2 dan VMnet3 untuk LAN1 dan LAN2 harus dibuat manual.

1. Buka **Edit → Virtual Network Editor** → klik **Change Settings** (Run as Administrator)
2. Cek apakah **VMnet2** dan **VMnet3** sudah ada di daftar:
   - Kalau sudah ada → lanjut ke verifikasi setting di bawah
   - Kalau belum ada → klik **Add Network** → pilih **VMnet2** → OK, ulangi untuk **VMnet3**

**Setting VMnet2 (LAN1 — Server Zone):**

| Setting | Nilai |
|---------|-------|
| Type | Host-only |
| Use local DHCP service | **Uncheck** (jangan dicentang) |
| Subnet IP | `10.10.10.0` |
| Subnet mask | `255.255.255.0` |
| Host virtual adapter IP | `10.10.10.254` |

**Setting VMnet3 (LAN2 — Host Zone):**

| Setting | Nilai |
|---------|-------|
| Type | Host-only |
| Use local DHCP service | **Uncheck** (jangan dicentang) |
| Subnet IP | `10.10.20.0` |
| Subnet mask | `255.255.255.0` |
| Host virtual adapter IP | `10.10.20.254` |

Klik **Apply → OK**.

> **Penting — jangan centang DHCP VMware:** pfSense yang bertugas sebagai DHCP server untuk LAN1 dan LAN2. Kalau DHCP VMware ikut aktif, akan ada dua DHCP server di satu network → conflict → VM lain dapat IP yang salah.

> **Penting — Host virtual adapter IP jangan `.1`:** VMware default assign `10.10.10.1` ke host adapter VMnet2, bentrok dengan IP LAN pfSense (`10.10.10.1`). Ganti ke `10.10.10.254` agar tidak conflict. Kalau dibiarkan conflict: ping ke `10.10.10.1` akan reply dari Windows host sendiri, bukan pfSense, dan Web GUI tidak bisa diakses.

### 1.3 Tambahkan 2 NIC untuk LAN1 dan LAN2

Setelah VMnet2 dan VMnet3 siap, tambahkan 2 network adapter ke VM pfSense:

1. Klik kanan VM `pfSense` → **Settings**
2. Klik **Add → Network Adapter → Finish**
   - Network connection: **Custom: VMnet2** (untuk LAN1)
3. Klik **Add → Network Adapter → Finish** lagi
   - Network connection: **Custom: VMnet3** (untuk LAN2)
4. Klik **OK**

Konfigurasi NIC pfSense **saat proses install** — gunakan **NAT** dulu di Adapter 1 agar pfSense bisa akses internet selama instalasi:

| Adapter | VMware Setting (saat install) | Fungsi |
|---------|-------------------------------|--------|
| Network Adapter 1 | **NAT** | WAN — internet via VMware NAT (sementara) |
| Network Adapter 2 | Custom: VMnet2 | LAN1 — Server Zone `10.10.10.0/24` |
| Network Adapter 3 | Custom: VMnet3 | LAN2 — Host Zone `10.10.20.0/24` |

> Setelah install selesai, WAN akan diganti dari NAT ke **Bridged** — lihat Step 2.1.

### 1.4 Mount ISO

1. Di **VM Settings → CD/DVD (SATA)**
2. Pilih **Use ISO image file** → browse ke ISO pfSense
3. Centang **Connect at power on**

---

## Step 2 — Install pfSense

1. Start VM → boot dari ISO pfSense
2. Tunggu sampai muncul menu boot → tekan **Enter** (atau tunggu countdown)
3. Layar **Welcome** → pilih **Install pfSense**
4. **Keymap:** pilih `>>> Continue with default keymap`
5. **Partitioning:** pilih **Auto (ZFS)** → Proceed → pilih disk (`ada0`) → **Install** → konfirmasi dengan `YES`
6. Tunggu proses instalasi selesai (~2-3 menit)
7. Ketika muncul prompt **Manual Configuration:** pilih **No**
8. **Reboot** → setelah reboot, **eject ISO** dari VMware (VM Settings → CD/DVD → pilih **Use physical drive** atau uncheck **Connect at power on**) agar tidak boot dari ISO lagi

### 2.1 Ganti WAN dari NAT ke Bridged (setelah install selesai)

Setelah pfSense berhasil diinstall dan bisa diakses via Web GUI, ganti Network Adapter 1 dari NAT ke Bridged agar pfSense terhubung langsung ke hotspot:

1. **Matikan VM pfSense** (Power off, bukan suspend)
2. Klik kanan VM → **Settings → Network Adapter 1**
3. Ganti dari **NAT** ke **Bridged: Connected directly to the physical network**
4. Centang **Replicate physical network connection state**
5. Klik **OK**

**Pastikan VMnet0 bridge ke adapter WiFi yang benar (wajib dicek):**

VMware Bridged mode default pakai `Automatic` — bisa salah pilih adapter (misal bridge ke Ethernet yang tidak aktif, bukan ke WiFi hotspot). Fix manual:

1. Buka **Edit → Virtual Network Editor** (Run as Administrator)
2. Pilih **VMnet0 (Bridged)**
3. Di bagian **"Bridged to:"** → ganti dari `Automatic` ke adapter **WiFi aktif** yang terhubung ke hotspot (misal: `Intel Wireless`, `Realtek WiFi`, dll)
4. **Apply → OK**
5. **Start VM pfSense** kembali

WAN pfSense akan otomatis dapat IP dari hotspot (`192.168.43.x`) via DHCP. Verifikasi di console pfSense — bagian atas harus muncul IP di `WAN (em0)`.

Konfigurasi NIC pfSense final setelah perubahan ini:

| Adapter | VMware Setting (final) | Fungsi |
|---------|------------------------|--------|
| Network Adapter 1 | **Bridged → WiFi adapter** | WAN — dapat IP dari hotspot `192.168.43.x` |
| Network Adapter 2 | Custom: VMnet2 | LAN1 — Server Zone `10.10.10.0/24` |
| Network Adapter 3 | Custom: VMnet3 | LAN2 — Host Zone `10.10.20.0/24` |

---

## Step 3 — Assign Interface

Setelah reboot, pfSense masuk ke console menu. Pilih **option 1 - Assign Interfaces**.

```
Do you want to set up VLANs now? → n

Enter the WAN interface name: em0      ← Adapter 1 (WAN/NAT saat install, nanti diganti Bridged)
Enter the LAN interface name: em1      ← Adapter 2 (LAN1 Server)
Enter optional interface name: em2     ← Adapter 3 (LAN2 Host) — bisa diisi atau skip dulu
Enter optional interface name:         ← kosong, tekan Enter

Do you want to proceed? → y
```

> **LAN2 bisa dikonfigurasi belakangan:** Kalau saat assign interface kamu hanya mengisi `em0` (WAN) dan `em1` (LAN1) lalu continue, itu tidak masalah. Interface `em2` untuk LAN2 bisa ditambahkan dan dikonfigurasi setelah install via Web GUI (Interfaces → Assignments) atau console option 1 dijalankan ulang.

> **Catatan:** Di VMware, interface pfSense biasanya bernama `em0`, `em1`, `em2`. Kalau tidak yakin mapping-nya, cek MAC address di VMware (VM Settings → Network Adapter → Advanced → MAC Address) dan cocokkan dengan yang muncul di console pfSense saat assign interface.

---

## Step 4 — Set IP Address

### 4.1 Set IP LAN1 (em1 → `10.10.10.1`)

Dari console menu, pilih **option 2 - Set interface(s) IP address** → pilih **em1 (LAN)**:

```
Configure IPv4 via DHCP? → n
Enter the new LAN IPv4 address: 10.10.10.1
Enter the new LAN IPv4 subnet bit count: 24
Enter the IPv4 upstream gateway: (kosong, tekan Enter)
Configure IPv6? → n
Enable DHCP server on LAN? → y
Enter start address: 10.10.10.100
Enter end address: 10.10.10.200
Revert to HTTP? → n
```

### 4.2 Set IP LAN2/OPT1 (em2 → `10.10.20.1`)

Pilih **option 2** lagi → pilih **em2 (OPT1)**:

```
Configure IPv4 via DHCP? → n
Enter the new OPT1 IPv4 address: 10.10.20.1
Enter the new OPT1 IPv4 subnet bit count: 24
Enter the IPv4 upstream gateway: (kosong, tekan Enter)
Configure IPv6? → n
Enable DHCP server on OPT1? → y
Enter start address: 10.10.20.100
Enter end address: 10.10.20.200
Revert to HTTP? → n
```

### 4.3 WAN (em0)

WAN akan otomatis mendapat IP dari hotspot via DHCP (`192.168.43.x`). Tidak perlu konfigurasi manual.

---

## Step 5 — Akses Web GUI

pfSense bisa dikonfigurasi lebih lanjut lewat web browser. Akses dari VM manapun yang ada di LAN1 atau LAN2:

```
URL   : https://10.10.10.1
User  : admin
Pass  : pfsense  (default, ganti setelah login pertama)
```

> **Catatan:** Browser akan warning "certificate not trusted" karena pfSense pakai self-signed cert. Klik **Advanced → Accept the Risk**.

---

## Step 6 — Konfigurasi Awal via Web GUI

### 6.1 Setup Wizard

Saat pertama login, pfSense akan jalankan Setup Wizard:

1. **General Information:** isi Hostname (`pfsense`), Domain (`lab.local`), DNS server (pakai `8.8.8.8` / `1.1.1.1`)
2. **Time Server:** biarkan default (pool.ntp.org)
3. **WAN:** biarkan DHCP
4. **LAN:** IP sudah `10.10.10.1/24`, biarkan
5. **Admin Password:** **ganti password default** → simpan di tempat aman
6. **Reload** → selesai

### 6.2 Aktifkan Interface OPT1 (LAN2)

By default OPT1 (em2/LAN2) belum aktif via GUI:

1. **Interfaces → OPT1**
2. Centang **Enable interface**
3. **Description:** ganti jadi `LAN2`
4. IPv4 Configuration Type: `Static IPv4`
5. IPv4 Address: `10.10.20.1 / 24`
6. **Save → Apply Changes**

### 6.3 Aktifkan DHCP di OPT1/LAN2

1. **Services → DHCP Server → LAN2**
2. Centang **Enable DHCP server on LAN2**
3. Range: `10.10.20.100` – `10.10.20.200`
4. **Save**

### 6.4 Firewall Rules — Allow LAN2 ke Internet

By default LAN1 sudah ada rule allow-all. LAN2 (OPT1) belum punya rule:

1. **Firewall → Rules → LAN2**
2. Klik **Add** (panah atas)
3. Isi:
   - Action: **Pass**
   - Interface: LAN2
   - Protocol: **Any**
   - Source: **LAN2 net**
   - Destination: **Any**
   - Description: `Allow LAN2 to anywhere`
4. **Save → Apply Changes**

### 6.5 Firewall Rules — Isolasi Antar Zone (Opsional tapi Recommended)

Untuk simulasi yang realistis, LAN1 dan LAN2 sebaiknya tidak bisa langsung saling akses kecuali ada rule eksplisit. Ini memaksa traffic melewati pfSense sehingga bisa dilog dan dideteksi Wazuh:

1. **Firewall → Rules → LAN1** → tambahkan rule:
   - Action: **Block**
   - Source: `LAN1 net`
   - Destination: `LAN2 net`
   - Description: `Block LAN1 to LAN2 (default isolasi)`

2. **Firewall → Rules → LAN2** → tambahkan rule:
   - Action: **Block**
   - Source: `LAN2 net`
   - Destination: `LAN1 net`
   - Description: `Block LAN2 to LAN1 (default isolasi)`

> **Catatan lab:** Rule block ini bisa dinonaktifkan sementara untuk skenario lateral movement — enable kembali setelah skenario selesai.

---

## Verifikasi

### Dari console pfSense (option 7 - Ping host):

```
Ping ke 8.8.8.8       → harus reply (WAN ke internet OK)
Ping ke 10.10.10.1    → harus reply (LAN1 gateway OK)
Ping ke 10.10.20.1    → harus reply (LAN2 gateway OK)
```

### Dari VM di LAN1 (misal Web-Server `10.10.10.10`):

```bash
ping 10.10.10.1     # gateway LAN1 → harus reply
ping 8.8.8.8        # internet via pfSense → harus reply
```

### Dari VM di LAN2 (misal Kali `10.10.20.100`):

```bash
ping 10.10.20.1     # gateway LAN2 → harus reply
ping 8.8.8.8        # internet via pfSense → harus reply
ping 10.10.10.10    # cross-zone → harus BLOCK (kalau rule isolasi aktif)
```

### Dashboard pfSense:

- **Status → Dashboard:** pastikan WAN dapat IP `192.168.43.x`
- **Status → DHCP Leases:** VM yang connect ke LAN1/LAN2 harus muncul di sini
- **Status → Traffic Graphs:** ada traffic saat VM ping ke internet

---

## Troubleshooting

| Masalah | Kemungkinan Penyebab | Solusi |
|---------|----------------------|--------|
| WAN tidak dapat IP | Bridged adapter salah pilih interface | Cek NIC mana yang aktif terhubung ke hotspot |
| Web GUI tidak bisa diakses | OPT1 belum diaktifkan | Aktifkan via console option 2 dulu |
| VM LAN2 tidak bisa internet | Tidak ada firewall rule di LAN2 | Tambahkan rule Allow LAN2 net → Any |
| Interface nama berbeda (vtnet bukan em) | Variasi driver VMware | Cek MAC address di VM Settings → Network Adapter → Advanced |
| Ping antar zone berhasil padahal ada block rule | Urutan rule salah | Rule block harus di atas rule allow di daftar |

---

## Selanjutnya

Setelah pfSense running dan terverifikasi, lanjut setup VM berikutnya:

1. **Web-Server** (`10.10.10.10`) — Ubuntu Server + DVWA
2. **WIN AD** (`10.10.10.20`) — Windows Server + Active Directory
3. **Windows PC** (`10.10.20.10`) — Victim workstation
4. **Compromise-Kali** (`10.10.20.100`) — Attacker VM

Semua VM tersebut tinggal set network adapter ke **Custom: VMnet2** (LAN1) atau **Custom: VMnet3** (LAN2) sesuai zona masing-masing, dan pfSense akan otomatis assign IP via DHCP.
