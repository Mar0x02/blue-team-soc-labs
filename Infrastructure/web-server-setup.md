# Web-Server Setup — Ubuntu Server (LAN1 Server Zone)

## Tujuan

Menginstall dan mengkonfigurasi Ubuntu Server 26.04 LTS sebagai **Web-Server** di LAN1 (Server Zone), yang nantinya jadi target web attack (DVWA). Tahap ini fokus base OS + network config dulu — DVWA menyusul di step terpisah setelah konektivitas ke pfSense terverifikasi.

- **IP Address:** `10.10.10.10/24`
- **Gateway:** `10.10.10.1` (pfSense LAN1)
- **Network Adapter:** Custom: VMnet2

---

## Prerequisites

- pfSense sudah running dan LAN1 (VMnet2) aktif — lihat [`pfsense-setup.md`](./pfsense-setup.md)
- ISO Ubuntu Server 26.04 LTS sudah didownload dari [ubuntu.com/download/server](https://ubuntu.com/download/server)
- VMware Workstation Pro sudah terinstall di PC
- Spesifikasi VM minimal: 2 CPU, 2 GB RAM, 25 GB storage, 1 NIC

---

## Step 1 — Buat VM di VMware Workstation Pro

1. **File → New Virtual Machine** → **Custom (advanced)** → Next
2. **Hardware compatibility:** biarkan default → Next
3. **Installer disc image file (ISO):** pilih ISO Ubuntu Server 26.04 LTS → Next
4. **Guest OS:** **Linux** → **Ubuntu 64-bit** → Next
5. **VM Name:** `Web-Server` → tentukan lokasi penyimpanan → Next
6. **Processors:** `2 processor` → Next
7. **Memory:** `2048 MB` (sesuaikan kalau RAM PC longgar, bisa naikkan ke 4096 MB) → Next
8. **Network:** pilih **Custom: VMnet2** (LAN1 Server Zone) → Next
9. **I/O Controller:** LSI Logic → Next
10. **Disk type:** SCSI → Next
11. **Disk:** Create a new virtual disk → `25 GB`, Store as single file → Next
12. **Finish**

> **Penting:** Jangan pilih NAT/Bridged — Web-Server langsung ke VMnet2 karena pfSense yang jadi gateway & DHCP untuk LAN1.

---

## Step 2 — Install Ubuntu Server

1. Start VM → boot dari ISO
2. **Language:** English (default) → Enter
3. **Keyboard configuration:** biarkan default (US) → Done
4. **Base installation type:** pilih **Ubuntu Server** (bukan minimized) → Done
5. **Network connections:** interface akan otomatis dapat IP DHCP dari pfSense (`10.10.10.100`–`10.10.10.200`) — biarkan dulu, static IP diset setelah install → Done
6. **Proxy configuration:** kosongkan → Done
7. **Ubuntu Archive Mirror:** biarkan default → Done
8. **Guided storage configuration:** **Use an entire disk** → biarkan default (LVM) → Done → Done → Confirm dengan **Continue**
9. **Profile setup:**
   - Your name: `anang` (atau sesuai preferensi)
   - Your server's name: `web-server`
   - Username: `anang`
   - Password: buat password yang aman
10. **Ubuntu Pro:** Skip for now
11. **SSH Setup:** centang **Install OpenSSH server** (wajib — akses remote nantinya) → Done
12. **Featured Server Snaps:** skip semua (tidak perlu untuk sekarang) → Done
13. Tunggu proses instalasi selesai → **Reboot Now**
14. Setelah reboot, **eject ISO** kalau VMware tidak auto-eject (VM Settings → CD/DVD → uncheck **Connect at power on**)

---

## Step 3 — Set Static IP

Login pakai username/password yang dibuat saat install, lalu edit netplan config:

```bash
ip a
# cek nama interface (biasanya ens33 atau enp0s3)

sudo nano /etc/netplan/50-cloud-init.yaml
```

Isi dengan konfigurasi berikut (sesuaikan nama interface):

```yaml
network:
  version: 2
  ethernets:
    ens33:
      dhcp4: no
      addresses:
        - 10.10.10.10/24
      routes:
        - to: default
          via: 10.10.10.1
      nameservers:
        addresses: [8.8.8.8, 1.1.1.1]
```

Apply config:

```bash
sudo netplan apply
ip a    # verifikasi IP sudah 10.10.10.10
```

> **Catatan:** Ubuntu Server 26.04 pakai `cloud-init` untuk network config default, makanya file netplan bernama `50-cloud-init.yaml`. Kalau `netplan apply` gagal karena file di-generate ulang oleh cloud-init tiap boot, disable cloud-init network config:
> ```bash
> sudo bash -c 'echo "network: {config: disabled}" > /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg'
> ```

---

## Step 4 — Update & Hardening Dasar

```bash
sudo apt update && sudo apt upgrade -y

# Set timezone
sudo timedatectl set-timezone Asia/Jakarta

# Enable firewall lokal (UFW) — opsional, karena pfSense sudah filter di layer network
sudo ufw allow OpenSSH
sudo ufw enable
```

---

## Verifikasi

### Dari VM Web-Server:

```bash
ping 10.10.10.1     # gateway LAN1 → harus reply
ping 8.8.8.8        # internet via pfSense NAT → harus reply
hostname -I          # harus muncul 10.10.10.10
```

### Dari pfSense (Status → DHCP Leases / ARP Table):

Karena IP di-set static, cek via **Diagnostics → ARP Table** — `10.10.10.10` harus muncul dengan MAC address VM Web-Server.

### SSH dari device lain di LAN1/LAN2 (atau dari Dell/M1 kalau firewall rule LAN2→LAN1 diizinkan):

```bash
ssh anang@10.10.10.10
```

---

## Troubleshooting

| Masalah | Kemungkinan Penyebab | Solusi |
|---------|----------------------|--------|
| Tidak dapat IP DHCP saat install | VMnet2 network adapter salah dipilih | Cek VM Settings → Network Adapter → harus **Custom: VMnet2** |
| `netplan apply` error / IP balik ke DHCP setelah reboot | cloud-init generate ulang netplan config | Disable cloud-init network config (lihat catatan Step 3) |
| Tidak bisa ping `8.8.8.8` tapi bisa ping `10.10.10.1` | Firewall rule LAN1 belum allow-all, atau NAT belum aktif di pfSense | Cek **Firewall → Rules → LAN1** dan **Firewall → NAT → Outbound** |
| SSH connection refused | OpenSSH server tidak terinstall saat setup | `sudo apt install openssh-server -y` lalu `sudo systemctl enable ssh` |

---

## Selanjutnya

Setelah Web-Server base OS terverifikasi (ping gateway + internet OK), lanjut install **DVWA** (Damn Vulnerable Web Application) di atas LAMP stack — jadi target web attack untuk skenario deteksi SQL injection, XSS, brute force, dll yang akan dideteksi Wazuh.
