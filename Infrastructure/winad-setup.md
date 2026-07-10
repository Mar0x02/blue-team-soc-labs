# WIN AD Setup — Windows Server 2025 (LAN1 Server Zone)

## Tujuan

Menginstall dan mengkonfigurasi Windows Server 2025 sebagai **WIN AD** di LAN1 (Server Zone), yang nantinya jadi Domain Controller (Active Directory) buat lab lateral movement, Kerberoasting, Pass-the-Hash, dll. Tahap ini fokus base OS + network config dulu — promosi jadi Domain Controller (AD DS) menyusul di step terpisah setelah konektivitas ke pfSense terverifikasi.

- **IP Address:** `10.10.10.20/24`
- **Gateway:** `10.10.10.1` (pfSense LAN1)
- **Network Adapter:** Custom: VMnet2

---

## Prerequisites

- pfSense sudah running dan LAN1 (VMnet2) aktif — lihat [`pfsense-setup.md`](./pfsense-setup.md)
- ISO Windows Server 2025 sudah didownload dari [Microsoft Evaluation Center](https://www.microsoft.com/evalcenter/) (Evaluation edition, 180 hari trial — cukup untuk lab)
- VMware Workstation Pro sudah terinstall di PC
- Spesifikasi VM minimal: 2 CPU, 4 GB RAM, 60 GB storage, 1 NIC

---

## Step 1 — Buat VM di VMware Workstation Pro

1. **File → New Virtual Machine** → **Custom (advanced)** → Next
2. **Hardware compatibility:** biarkan default → Next
3. **Installer disc image file (ISO):** pilih ISO Windows Server 2025 → Next
4. **Guest OS:** **Windows** → **Windows Server 2025** (kalau belum ada di list, pilih **Windows Server 2022** — cukup untuk kompatibilitas VMware Tools) → Next
5. **VM Name:** `WIN-AD` → tentukan lokasi penyimpanan → Next
6. **Processors:** `2 processor` → Next
7. **Memory:** `4096 MB` (naikkan ke 6144 MB kalau RAM PC longgar — AD DS + DNS lumayan makan resource) → Next
8. **Network:** pilih **Custom: VMnet2** (LAN1 Server Zone) → Next
9. **I/O Controller:** LSI Logic SAS → Next
10. **Disk type:** SCSI → Next
11. **Disk:** Create a new virtual disk → `60 GB`, Store as single file → Next
12. **Finish**

> **Penting:** Sama kayak Web-Server, jangan pilih NAT/Bridged — WIN AD langsung ke VMnet2 karena pfSense yang jadi gateway & DHCP untuk LAN1.

---

## Step 2 — Install Windows Server 2025

1. Start VM → boot dari ISO
2. **Language, Time, Keyboard:** biarkan default (atau sesuaikan) → Next
3. Klik **Install now**
4. **Select the operating system:** pilih **Windows Server 2025 Standard/Datacenter (Desktop Experience)** — pakai versi Desktop Experience (bukan Core) biar ada GUI, lebih gampang buat lab
5. Accept license terms → Next
6. **Installation type:** **Custom: Install Windows only (advanced)**
7. Pilih disk yang tadi dibuat → Next
8. Tunggu proses instalasi (~15-20 menit) → VM restart otomatis
9. Setelah restart, set password Administrator (harus kombinasi huruf besar/kecil, angka, simbol)
10. Login pakai `Administrator` dan password yang baru dibuat

---

## Step 3 — Install VMware Tools

VMware Tools penting biar resolusi layar pas, clipboard sharing, dan driver network lebih stabil:

1. Di menu VM → **Install VMware Tools** (atau lewat menu **VM → Removable Devices** kalau ISO ter-mount otomatis)
2. Buka File Explorer → drive CD VMware Tools → jalankan `setup64.exe`
3. Ikuti wizard install (default aja) → restart VM setelah selesai

---

## Step 4 — Set Static IP

1. Buka **Server Manager** (biasanya auto-open saat login) → **Local Server**
2. Klik link IPv4 address yang muncul di sebelah **Ethernet** (biasanya "IPv4 address assigned by DHCP, IPv6 enabled")
3. Klik kanan interface network → **Properties**
4. Pilih **Internet Protocol Version 4 (TCP/IPv4)** → **Properties**
5. Pilih **Use the following IP address:**

```
IP address       : 10.10.10.20
Subnet mask      : 255.255.255.0
Default gateway  : 10.10.10.1
```

6. Pilih **Use the following DNS server addresses:**

```
Preferred DNS server : 127.0.0.1   (server ini sendiri nantinya jadi DNS setelah AD DS)
Alternate DNS server : 8.8.8.8      (sementara, sebelum AD DS aktif)
```

> **Catatan:** Preferred DNS `127.0.0.1` baru berfungsi penuh setelah AD DS + DNS Role terinstall (step selanjutnya). Untuk sekarang, kalau `127.0.0.1` bikin internet gak jalan duluan, pakai `8.8.8.8` dulu sebagai preferred, nanti diganti balik pas promosi Domain Controller.

7. **OK** → **Close**

---

## Step 5 — Rename Computer (Opsional tapi Recommended)

Nama komputer default (`WIN-XXXXXXX`) sebaiknya diganti sebelum promosi AD DS, karena rename setelah jadi Domain Controller lebih ribet:

1. **Server Manager → Local Server** → klik nama komputer di samping "Computer name"
2. **Change...** → isi nama baru, misal `WIN-AD-DC01`
3. Restart saat diminta

---

## Step 6 — Update Windows (Opsional)

```powershell
# Buka PowerShell as Administrator
Install-Module PSWindowsUpdate -Force
Get-WindowsUpdate
Install-WindowsUpdate -AcceptAll -AutoReboot
```

> Update ini opsional untuk lab isolated — boleh di-skip kalau mau langsung lanjut ke AD DS, tapi disarankan minimal sekali update biar gak ada critical bug yang ganggu instalasi role AD DS nanti.

---

## Verifikasi

### Dari VM WIN AD (PowerShell atau CMD):

```powershell
ping 10.10.10.1     # gateway LAN1 → harus reply
ping 8.8.8.8        # internet via pfSense NAT → harus reply
ipconfig /all       # pastikan IPv4 Address = 10.10.10.20
```

### Dari pfSense (Diagnostics → ARP Table):

`10.10.10.20` harus muncul dengan MAC address VM WIN AD.

### RDP dari device lain di LAN1/LAN2 (kalau firewall rule mengizinkan):

```
mstsc /v:10.10.10.20
```

> **Catatan:** Remote Desktop belum aktif by default. Kalau mau enable: **Server Manager → Local Server → Remote Desktop → Enable**.

---

## Troubleshooting

| Masalah | Kemungkinan Penyebab | Solusi |
|---------|----------------------|--------|
| Tidak dapat IP DHCP saat instalasi VMware Tools | VMnet2 network adapter salah dipilih | Cek VM Settings → Network Adapter → harus **Custom: VMnet2** |
| Resolusi layar kecil / mouse gak smooth | VMware Tools belum terinstall | Ulangi Step 3 |
| Tidak bisa ping `8.8.8.8` tapi bisa ping `10.10.10.1` | Firewall rule LAN1 belum allow-all, atau DNS preferred `127.0.0.1` belum ada service DNS jalan | Set DNS preferred sementara ke `8.8.8.8` dulu (lihat catatan Step 4) |
| Instalasi ISO lambat / stuck | Alokasi RAM/CPU VM terlalu kecil | Naikkan minimal 4GB RAM, 2 vCPU sebelum install |

---

## Selanjutnya

Setelah WIN AD base OS terverifikasi (ping gateway + internet OK, static IP `10.10.10.20` aktif), lanjut **promosi ke Domain Controller**:

1. Install role **Active Directory Domain Services (AD DS)** + **DNS Server**
2. Promosikan jadi Domain Controller baru, buat domain forest (misal `lab.local`)
3. Buat OU (Organizational Unit), user, dan group buat simulasi environment enterprise
4. Join VM Windows 7/XP di LAN2 ke domain (setelah firewall rule LAN1↔LAN2 dikonfigurasi untuk lab tertentu)

Ini akan jadi writeup terpisah: `winad-promotion.md`.
