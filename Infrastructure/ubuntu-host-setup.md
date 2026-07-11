# Ubuntu Host Setup — Victim Workstation Linux (LAN2 Host Zone)

## Tujuan

Menginstall dan mengkonfigurasi Ubuntu Desktop 26.04 LTS sebagai **victim workstation Linux** di LAN2 (Host Zone). Tahap ini fokus base OS + network config dulu — simulasi serangan/deteksi di sisi Linux dibahas di lab terpisah setelah base OS terverifikasi.

- **IP Address:** `10.10.20.30/24`
- **Gateway:** `10.10.20.1` (pfSense LAN2)
- **Network Adapter:** Custom: VMnet3

---

## Prerequisites

- pfSense sudah running dan LAN2 (VMnet3) aktif — lihat [`pfsense-setup.md`](./pfsense-setup.md)
- ISO Ubuntu Desktop 26.04 LTS sudah tersedia
- VMware Workstation Pro sudah terinstall di PC
- Spesifikasi VM minimal: 2 CPU, 4 GB RAM, 40 GB storage, 1 NIC

---

## Step 1 — Buat VM di VMware Workstation Pro

1. **File → New Virtual Machine** → **Custom (advanced)** → Next
2. **Hardware compatibility:** biarkan default → Next
3. **Installer disc image file (ISO):** pilih ISO Ubuntu Desktop 26.04 LTS → Next
4. **Guest OS:** **Linux** → **Ubuntu 64-bit** → Next
5. **VM Name:** `Ubuntu-Host` → tentukan lokasi penyimpanan → Next
6. **Firmware type:** **UEFI** (default modern untuk Ubuntu 64-bit)
7. **Processors:** `2 processors` → Next
8. **Memory:** `4096 MB` → Next
9. **Network:** pilih **Custom: VMnet3** (LAN2 Host Zone) → Next
10. **I/O Controller:** NVMe atau LSI Logic (default) → Next
11. **Disk type:** NVMe atau SCSI (default) → Next
12. **Disk:** Create a new virtual disk → `40 GB`, Store as single file → Next
13. **Finish**

> **Penting:** Sama seperti VM lain di LAN2, jangan pilih NAT/Bridged — Ubuntu Host langsung ke **VMnet3** karena pfSense yang jadi gateway & DHCP untuk LAN2.

---

## Step 2 — Install Ubuntu Desktop

1. Start VM → boot dari ISO
2. **Try or Install Ubuntu** → pilih **Install Ubuntu**
3. **Keyboard layout:** biarkan default (English US) → Continue
4. **Updates and other software:** pilih **Normal installation**, centang **Download updates while installing Ubuntu** → Continue
5. **Installation type:** **Erase disk and install Ubuntu** (disk VM masih kosong, aman) → Install Now → Continue (confirm partisi)
6. **Where are you:** sesuaikan timezone → Continue
7. **Who are you:**
   - **Your name:** `victim`
   - **Computer name:** `ubuntu-victim`
   - **Username:** `victim`
   - **Password:** buat password (boleh sengaja lemah untuk lab, catat di file credentials)
   - Pilih **Require my password to log in**
8. Tunggu instalasi selesai → **Restart Now** → cabut ISO saat diminta → Enter

---

## Step 3 — Install VMware Tools (open-vm-tools)

Ubuntu modern sudah bundling `open-vm-tools`, tapi pastikan up to date:

```bash
sudo apt update
sudo apt install -y open-vm-tools open-vm-tools-desktop
sudo reboot
```

---

## Step 4 — Set Static IP

Ubuntu Desktop 26.04 pakai Netplan (backend NetworkManager). Cara termudah lewat GUI:

1. **Settings → Network** → klik gear di sebelah koneksi wired aktif
2. Tab **IPv4** → pilih **Manual**

```
Address        : 10.10.20.30
Netmask        : 255.255.255.0
Gateway        : 10.10.20.1
DNS            : 8.8.8.8, 1.1.1.1
```

3. **Apply** → toggle koneksi wired off/on (atau restart NetworkManager) biar setting kepakai

Alternatif via terminal (cek nama interface dulu dengan `ip a`, biasanya `ens33` atau `ens160`):

```bash
sudo nmcli con mod "Wired connection 1" ipv4.addresses 10.10.20.30/24
sudo nmcli con mod "Wired connection 1" ipv4.gateway 10.10.20.1
sudo nmcli con mod "Wired connection 1" ipv4.dns "8.8.8.8 1.1.1.1"
sudo nmcli con mod "Wired connection 1" ipv4.method manual
sudo nmcli con up "Wired connection 1"
```

---

## Step 5 — Disable UFW (Firewall)

Sama seperti VM victim lain, ini VM yang sengaja jadi target attack, filtering utama sudah dihandle pfSense:

```bash
sudo ufw disable
sudo ufw status   # pastikan output: Status: inactive
```

---

## Verifikasi

### Dari VM Ubuntu Host (terminal):

```bash
ip a                  # pastikan IP address = 10.10.20.30
ping -c 4 10.10.20.1  # gateway LAN2 → harus reply
ping -c 4 8.8.8.8     # internet via pfSense NAT → harus reply
```

### Dari pfSense (Diagnostics → ARP Table):

`10.10.20.30` harus muncul dengan MAC address VM Ubuntu Host.

### Cek isolasi LAN1 (harus GAGAL selama rule isolasi masih aktif):

```bash
ping -c 4 10.10.10.10   # Web-Server (LAN1) → harus GAGAL
```

---

## Troubleshooting

| Masalah | Kemungkinan Penyebab | Solusi |
|---------|----------------------|--------|
| VM gak mau boot dari ISO | Firmware/boot order salah | Cek VM Settings → Options → Advanced → Firmware type → **UEFI**, pastikan ISO ke-mount di CD/DVD |
| Tidak dapat IP DHCP saat install | VMnet3 network adapter salah dipilih | Cek VM Settings → Network Adapter → harus **Custom: VMnet3** |
| Static IP gak kepakai setelah apply di GUI | NetworkManager belum reconnect | Toggle wired connection off/on, atau `sudo nmcli con down "Wired connection 1" && sudo nmcli con up "Wired connection 1"` |
| Resolusi layar kecil/gak fullscreen | open-vm-tools belum jalan/belum reboot | Pastikan `open-vm-tools-desktop` terinstall, reboot VM |
| Tidak bisa ping `8.8.8.8` tapi bisa ping `10.10.20.1` | Firewall rule LAN2 belum allow-all, atau NAT belum aktif di pfSense | Cek **Firewall → Rules → LAN2** dan **Firewall → NAT → Outbound** di pfSense |
| Bisa ping `8.8.8.8` tapi gak bisa `ping google.com` / browsing gagal | Field DNS di Step 4 belum diisi (kelewat pas Manual IPv4) | Isi ulang DNS `8.8.8.8, 1.1.1.1` di **Settings → Network → IPv4**, lalu cek `resolvectl status` |

---

## Catatan Keamanan Lab

Ubuntu Host ini sengaja dikonfigurasi minim hardening (UFW off, password lab) — target ideal buat simulasi serangan sisi Linux (misalnya privilege escalation, lateral movement, atau abuse service lokal). Karena posisinya di LAN2 di belakang pfSense, exposure ke luar sudah terbatas — tapi tetap jangan install software tambahan yang gak perlu atau browsing sembarangan dari VM ini.
