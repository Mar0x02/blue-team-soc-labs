# Windows 7 Setup — Victim Workstation (LAN2 Host Zone)

## Tujuan

Menginstall dan mengkonfigurasi Windows 7 Professional 32-bit sebagai **victim workstation** di LAN2 (Host Zone). Tahap ini fokus base OS + network config dulu — join domain `lab.local` menyusul di step terpisah setelah konektivitas ke pfSense terverifikasi.

- **IP Address:** `10.10.20.10/24`
- **Gateway:** `10.10.20.1` (pfSense LAN2)
- **Network Adapter:** Custom: VMnet3

---

## Prerequisites

- pfSense sudah running dan LAN2 (VMnet3) aktif — lihat [`pfsense-setup.md`](./pfsense-setup.md)
- WIN AD (`lab.local`) sudah aktif — lihat [`winad-promotion.md`](./winad-promotion.md) (buat referensi nanti, join domain di step terpisah)
- ISO Windows 7 Professional 32-bit sudah tersedia
- VMware Workstation Pro sudah terinstall di PC
- Spesifikasi VM minimal: 1 CPU, 2 GB RAM, 40 GB storage, 1 NIC

---

## Step 1 — Buat VM di VMware Workstation Pro

1. **File → New Virtual Machine** → **Custom (advanced)** → Next
2. **Hardware compatibility:** biarkan default → Next
3. **Installer disc image file (ISO):** pilih ISO Windows 7 Professional 32-bit → Next
4. **Guest OS:** **Windows** → **Windows 7** (VMware otomatis sesuaikan ke 32-bit kalau ISO terdeteksi 32-bit) → Next
5. **VM Name:** `Windows-7` → tentukan lokasi penyimpanan → Next
6. **Firmware type:** **BIOS** (Windows 7 32-bit gak support boot UEFI dengan baik — beda dari WIN AD yang pakai UEFI)
7. **Processors:** `1 processor` → Next
8. **Memory:** `2048 MB` (Windows 7 32-bit maksimal efektif kenali RAM ~3.2GB, 2GB udah cukup buat lab) → Next
9. **Network:** pilih **Custom: VMnet3** (LAN2 Host Zone) → Next
10. **I/O Controller:** LSI Logic → Next
11. **Disk type:** SCSI → Next
12. **Disk:** Create a new virtual disk → `40 GB`, Store as single file → Next
13. **Finish**

> **Penting:** Sama seperti VM lain, jangan pilih NAT/Bridged — Windows 7 langsung ke **VMnet3** karena pfSense yang jadi gateway & DHCP untuk LAN2.

> **Catatan Firmware:** Kalau di VM Settings versi kamu gak ada opsi pilih firmware type saat New VM Wizard, cek setelahnya di **VM Settings → Options → Advanced → Firmware type** dan pastikan **BIOS**, bukan UEFI.

---

## Step 2 — Install Windows 7

1. Start VM → boot dari ISO
2. **Language, Time, Keyboard:** biarkan default → Next
3. Klik **Install now**
4. **Product key:** masukkan kalau ada, atau **skip** (isi nanti setelah instalasi)
5. **Select the operating system:** pilih **Windows 7 Professional** (32-bit)
6. Accept license terms → Next
7. **Installation type:** **Custom (advanced)**
8. Pilih disk yang tadi dibuat → **New** → **Apply** → **Next**
9. Tunggu proses instalasi (~15-20 menit) → VM restart beberapa kali otomatis
10. **Set up Windows:**
    - Username: `victim` (atau sesuai preferensi)
    - Computer name: `WIN7-VICTIM`
    - Password: buat password (boleh sengaja lemah untuk simulasi lab, tapi catat di file credentials)
11. **Product key screen (kalau muncul):** skip aja, aktivasi bisa dilakukan/diabaikan belakangan untuk lab isolated
12. **Network location:** pilih **Work network** (biar firewall profile lebih permisif untuk keperluan lab, dibanding "Public")

---

## Step 3 — Install VMware Tools

1. Menu VM → **Install VMware Tools**
2. Buka **Computer** → drive CD VMware Tools → jalankan `setup.exe` (versi 32-bit)
3. Ikuti wizard install (default) → restart VM setelah selesai

> VMware Tools penting di Windows 7 buat driver network yang stabil, resolusi layar, dan clipboard sharing.

---

## Step 4 — Set Static IP

1. **Control Panel → Network and Internet → Network and Sharing Center**
2. **Change adapter settings** (sidebar kiri)
3. Klik kanan **Local Area Connection** → **Properties**
4. Pilih **Internet Protocol Version 4 (TCP/IPv4)** → **Properties**
5. Pilih **Use the following IP address:**

```
IP address       : 10.10.20.10
Subnet mask       : 255.255.255.0
Default gateway   : 10.10.20.1
```

6. Pilih **Use the following DNS server addresses:**

```
Preferred DNS server : 8.8.8.8
Alternate DNS server  : 1.1.1.1
```

> **Catatan:** DNS masih diarahkan ke publik dulu (`8.8.8.8`) karena belum join domain. Nanti pas proses join domain `lab.local` (step terpisah), DNS bakal diganti ke `10.10.10.20` (WIN AD) supaya bisa resolve domain.

7. **OK** → **Close**

---

## Step 5 — Matikan/Sesuaikan Windows Firewall (Opsional, untuk kebutuhan lab)

Karena ini VM **victim** yang sengaja jadi target skenario attack, dan filtering utama sudah dihandle pfSense di layer network:

1. **Control Panel → Windows Firewall → Turn Windows Firewall on or off**
2. **Turn off Windows Firewall** untuk kedua profile (Home/Work dan Public)

> **Catatan:** Ini best practice yang dibalik sengaja untuk kebutuhan lab (biar traffic attack gak keblok duluan sebelum sempat dideteksi Wazuh). Untuk VM yang bukan target attack, firewall sebaiknya tetap aktif.

---

## Verifikasi

### Dari VM Windows 7 (Command Prompt):

```cmd
ping 10.10.20.1     # gateway LAN2 → harus reply
ping 8.8.8.8        # internet via pfSense NAT → harus reply
ipconfig /all        # pastikan IPv4 Address = 10.10.20.10
```

### Dari pfSense (Diagnostics → ARP Table):

`10.10.20.10` harus muncul dengan MAC address VM Windows 7.

### Cek isolasi LAN1 (harus GAGAL selama rule isolasi masih aktif):

```cmd
ping 10.10.10.10    # Web-Server (LAN1) → harus GAGAL selama rule block LAN2→LAN1 aktif
```

> Ini hasil yang **benar** sesuai desain isolasi. Nanti pas mau join domain (`10.10.10.20` di LAN1), rule ini perlu di-adjust sementara — dibahas di writeup join domain.

---

## Troubleshooting

| Masalah | Kemungkinan Penyebab | Solusi |
|---------|----------------------|--------|
| VM gak mau boot dari ISO | Firmware type UEFI dipilih, bukan BIOS | Cek VM Settings → Options → Advanced → Firmware type → ganti **BIOS** |
| Tidak dapat IP DHCP saat install | VMnet3 network adapter salah dipilih | Cek VM Settings → Network Adapter → harus **Custom: VMnet3** |
| Resolusi layar kecil / driver network gak kedetect | VMware Tools belum terinstall | Ulangi Step 3 |
| Tidak bisa ping `8.8.8.8` tapi bisa ping `10.10.20.1` | Firewall rule LAN2 belum allow-all, atau NAT belum aktif di pfSense | Cek **Firewall → Rules → LAN2** dan **Firewall → NAT → Outbound** di pfSense |
