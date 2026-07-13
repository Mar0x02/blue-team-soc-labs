# Windows XP Setup — Victim Workstation Legacy (LAN2 Host Zone)

## Tujuan

Menginstall dan mengkonfigurasi Windows XP Professional SP3 sebagai **victim workstation legacy** di LAN2 (Host Zone). Tahap ini fokus base OS + network config dulu — join domain `lab.local` (kalau memungkinkan, lihat catatan kompatibilitas di bawah) dibahas terpisah setelah base OS terverifikasi.

- **IP Address:** `10.10.20.20/24`
- **Gateway:** `10.10.20.1` (pfSense LAN2)
- **Network Adapter:** Custom: VMnet3

> **Catatan kompatibilitas domain join:** Windows XP (2001) cuma support protokol lama (SMBv1, NTLMv1, LDAP simple bind) yang kemungkinan besar sudah di-disable/deprecated secara default di WIN AD (Windows Server 2025). Base OS + network di writeup ini gak kena masalah ini — tapi domain join nanti kemungkinan butuh penyesuaian tambahan di WIN AD (enable legacy protocol) atau bisa jadi XP dibiarkan **workgroup-only** sebagai simulasi legacy system yang gak terintegrasi domain (skenario ini realistis juga — banyak perusahaan beneran punya legacy machine yang gak di-domain-join).

---

## Prerequisites

- pfSense sudah running dan LAN2 (VMnet3) aktif — lihat [`pfsense-setup.md`](./pfsense-setup.md)
- ISO Windows XP Professional SP3 sudah tersedia
- VMware Workstation Pro sudah terinstall di PC
- Spesifikasi VM minimal: 1 CPU, 1 GB RAM, 20 GB storage, 1 NIC

---

## Step 1 — Buat VM di VMware Workstation Pro

1. **File → New Virtual Machine** → **Custom (advanced)** → Next
2. **Hardware compatibility:** biarkan default (atau turunkan ke versi lama kalau VMware kasih warning kompatibilitas XP) → Next
3. **Installer disc image file (ISO):** pilih ISO Windows XP Professional SP3 → Next
4. **Guest OS:** **Windows** → **Windows XP Professional** → Next
5. **VM Name:** `Windows-XP` → tentukan lokasi penyimpanan → Next
6. **Firmware type:** **BIOS** (wajib — Windows XP sama sekali gak support UEFI)
7. **Processors:** `1 processor` → Next
8. **Memory:** `1024 MB` (XP jalan ringan, 512MB-1GB cukup) → Next
9. **Network:** pilih **Custom: VMnet3** (LAN2 Host Zone) → Next
10. **I/O Controller:** BusLogic atau LSI Logic (XP kadang lebih stabil dengan **BusLogic** — kalau install gagal detect disk, coba ganti ke BusLogic) → Next
11. **Disk type:** SCSI → Next
12. **Disk:** Create a new virtual disk → `20 GB`, Store as single file → Next
13. **Finish**

> **Penting:** Sama seperti VM lain di LAN2, jangan pilih NAT/Bridged — Windows XP langsung ke **VMnet3**.

---

## Step 2 — Install Windows XP

1. Start VM → boot dari ISO
2. Tekan tombol apa saja kalau muncul **"Press any key to boot from CD..."**
3. Setup akan load driver dasar (layar biru khas installer XP)
4. **Welcome to Setup:** tekan **Enter** untuk install
5. **License Agreement:** tekan **F8** untuk agree
6. **Partisi disk:** pilih unpartitioned space → tekan **C** untuk create partition → gunakan seluruh disk → Enter
7. **Format partition:** pilih **NTFS (Quick)** → Enter, tunggu format selesai
8. Setup copy file, VM restart otomatis beberapa kali
9. **Regional and Language Options:** biarkan default → Next
10. **Personalize:** isi Name & Organization → Next
11. **Product Key:** masukkan kalau ada
12. **Computer name:** `winxp-ef16ad5b7`, **Administrator password:** buat password (boleh sengaja lemah untuk lab, catat di file credentials)
13. **Date and Time:** sesuaikan timezone → Next
14. **Network Settings:** pilih **Typical settings** (akan diatur ulang jadi static di Step 4)
15. **Workgroup or Computer Domain:** biarkan default **WORKGROUP** dulu → Next
16. Tunggu instalasi selesai, VM restart final

---

## Step 3 — Install VMware Tools

1. Menu VM → **Install VMware Tools**
2. **My Computer** → drive CD VMware Tools → jalankan `setup.exe`
3. Ikuti wizard install (default) → restart VM setelah selesai

> VMware Tools di XP kadang perlu versi lama/legacy — kalau installer modern gak jalan, VMware Workstation biasanya otomatis kasih versi yang kompatibel untuk guest OS lawas.

---

## Step 4 — Set Static IP

1. **Start → Control Panel → Network Connections**
2. Klik kanan **Local Area Connection** → **Properties**
3. Pilih **Internet Protocol (TCP/IP)** → **Properties**
4. Pilih **Use the following IP address:**

```
IP address       : 10.10.20.20
Subnet mask       : 255.255.255.0
Default gateway   : 10.10.20.1
```

5. Pilih **Use the following DNS server addresses:**

```
Preferred DNS server : 8.8.8.8
Alternate DNS server  : 1.1.1.1
```

6. **OK** → **OK**

---

## Step 5 — Disable Windows Firewall (ICF)

Sama seperti Windows 7, ini VM victim yang sengaja jadi target attack, filtering utama sudah dihandle pfSense:

1. **Control Panel → Windows Firewall**
2. Pilih **Off (not recommended)**
3. **OK**

---

## Step 6 — Install Service Pack 3 (kalau ISO belum slipstream SP3)

Kalau ISO yang dipakai masih XP RTM/SP2, disarankan update ke SP3 (patch security terakhir untuk XP, banyak lab attack tools yang assume minimal SP3):

```
Download: Windows XP Service Pack 3 (WindowsXP-KB936929-SP3-x86-ENU.exe)
Jalankan installer → ikuti wizard → restart
```

> Karena XP sudah EOL, download SP3 dari sumber terpercaya (Microsoft archive/Internet Archive), bukan sembarang mirror.

---

## Verifikasi

### Dari VM Windows XP (Command Prompt):

```cmd
ping 10.10.20.1     rem gateway LAN2 → harus reply
ping 8.8.8.8        rem internet via pfSense NAT → harus reply
ipconfig /all         rem pastikan IP Address = 10.10.20.20
```

### Dari pfSense (Diagnostics → ARP Table):

`10.10.20.20` harus muncul dengan MAC address VM Windows XP.

### Cek isolasi LAN1 (harus GAGAL selama rule isolasi masih aktif):

```cmd
ping 10.10.10.10    rem Web-Server (LAN1) → harus GAGAL
```

---

## Troubleshooting

| Masalah | Kemungkinan Penyebab | Solusi |
|---------|----------------------|--------|
| Installer gak detect hard disk | I/O Controller SCSI (LSI Logic) gak dikenali XP | Ganti ke **BusLogic** di VM Settings, atau pakai disk type **IDE** kalau masih gagal |
| VM gak mau boot dari ISO | Firmware UEFI kepilih, bukan BIOS | Cek VM Settings → Options → Advanced → Firmware type → **BIOS** |
| Tidak dapat IP DHCP saat install | VMnet3 network adapter salah dipilih | Cek VM Settings → Network Adapter → harus **Custom: VMnet3** |
| VMware Tools installer error/gak jalan | Versi VMware Tools terlalu baru untuk XP | Cek versi legacy VMware Tools, biasanya VMware auto-detect dan tawarin versi kompatibel |
| Tidak bisa ping `8.8.8.8` tapi bisa ping `10.10.20.1` | Firewall rule LAN2 belum allow-all, atau NAT belum aktif di pfSense | Cek **Firewall → Rules → LAN2** dan **Firewall → NAT → Outbound** di pfSense |

---

## Catatan Keamanan Lab

Windows XP ini **sengaja outdated dan vulnerable** (EOL sejak 2014, gak dapat security patch lagi) — target ideal buat simulasi exploit lawas (MS08-067, EternalBlue/MS17-010, dll). Karena posisinya di LAN2 di belakang pfSense, exposure ke luar sudah terbatas — tapi tetap jangan install software tambahan yang gak perlu atau browsing sembarangan dari VM ini.
