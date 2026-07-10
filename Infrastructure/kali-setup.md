# Kali Linux Setup — External Attacker (Hotspot Zone)

## Tujuan

Menginstall Kali Linux sebagai VM di PC, tapi diposisikan **di luar firewall pfSense** — connect langsung ke jaringan hotspot (`192.168.43.x`), sama seperti WAN interface pfSense, M1, dan Dell. Kali berperan sebagai **external attacker** yang menyerang lab dari luar, mensimulasikan threat actor di internet/jaringan publik.

- **IP Address:** DHCP dari hotspot (`192.168.43.x`, sama seperti WAN pfSense)
- **Network Adapter:** **Bridged** (langsung ke adapter WiFi yang connect ke hotspot — bukan VMnet2/VMnet3)

---

## Prerequisites

- ISO Kali Linux sudah didownload dari [kali.org/get-kali](https://www.kali.org/get-kali/) — pilih **Installer** (bukan Live, biar persistent) atau **Virtual Machines** (pre-built VMware image, lebih cepat)
- VMware Workstation Pro sudah terinstall di PC
- Spesifikasi VM minimal: 2 CPU, 4 GB RAM, 40 GB storage, 1 NIC

---

## Step 1 — Buat VM di VMware Workstation Pro

> Kalau kamu download **pre-built VMware image** dari Kali (`.vmx`/`.ova`), langsung skip ke Step 2 — tinggal **File → Open** file `.vmx`-nya, gak perlu buat VM manual dari ISO.

Kalau pakai **ISO installer**:

1. **File → New Virtual Machine** → **Custom (advanced)** → Next
2. **Hardware compatibility:** biarkan default → Next
3. **Installer disc image file (ISO):** pilih ISO Kali Linux → Next
4. **Guest OS:** **Linux** → **Debian 12.x 64-bit** (Kali berbasis Debian) → Next
5. **VM Name:** `Kali` → tentukan lokasi penyimpanan → Next
6. **Processors:** `2 processor` → Next
7. **Memory:** `4096 MB` → Next
8. **Network:** pilih **Use bridged networking** → Next
9. **I/O Controller:** LSI Logic → Next
10. **Disk type:** SCSI → Next
11. **Disk:** Create a new virtual disk → `40 GB`, Store as single file → Next
12. **Finish**

> **Penting — beda dari VM lain di lab ini:** Kali **wajib Bridged**, bukan Custom: VMnet2/VMnet3. Kalau salah pilih VMnet2/3, Kali malah masuk ke LAN1/LAN2 di belakang firewall — itu bikin dia bukan lagi "external attacker", tapi jadi internal host, merusak skenario lab.

### Pastikan VMnet0 (Bridged) mengarah ke adapter WiFi yang benar

Sama seperti setup WAN pfSense — cek dulu:

1. **Edit → Virtual Network Editor** (Run as Administrator)
2. Pilih **VMnet0 (Bridged)**
3. **"Bridged to:"** → pastikan mengarah ke adapter **WiFi aktif** yang connect ke hotspot (bukan Ethernet mati atau adapter lain)
4. **Apply → OK**

---

## Step 2 — Install Kali Linux

1. Start VM → boot dari ISO
2. Pilih **Graphical Install**
3. **Language, Location, Keyboard:** sesuaikan (English/Indonesia) → Continue
4. **Hostname:** `kali`
5. **Domain name:** kosongkan
6. **Set up users and passwords:** buat username & password (jangan pakai default `kali`/`kali` demi sedikit hardening, meski ini VM attacker)
7. **Partition disk:** **Guided - use entire disk** → pilih disk → **All files in one partition** → Finish partitioning → write changes to disk → **Yes**
8. **Software selection:** biarkan default (**Desktop environment + top10 tools**, atau centang **default tools** kalau versi installer menu-nya beda)
9. Tunggu proses instalasi (~15-30 menit tergantung pilihan software)
10. **Install GRUB boot loader:** Yes → pilih disk (`/dev/sda`)
11. Reboot setelah selesai, eject ISO kalau perlu

---

## Step 3 — Update & Install VMware Tools (open-vm-tools)

```bash
sudo apt update && sudo apt upgrade -y

# VMware Tools versi open-source, lebih ringan & direkomendasikan untuk Kali
sudo apt install open-vm-tools open-vm-tools-desktop -y
sudo reboot
```

---

## Verifikasi

### Cek IP yang didapat dari hotspot:

```bash
ip a
# atau
hostname -I
```

Harus muncul IP di range hotspot, misal `192.168.43.x` — **catat IP ini**, dipakai buat update tabel IP di [`network-topology.md`](./network-topology.md) (ganti placeholder `192.168.43.x` jadi IP aktual).

### Cek koneksi internet:

```bash
ping 8.8.8.8
```

### Cek Kali TIDAK bisa akses LAN1/LAN2 tanpa rule tambahan (verifikasi isolasi firewall):

```bash
ping 10.10.10.10    # Web-Server → harus GAGAL (timeout) selama belum ada NAT/firewall rule WAN→LAN1
ping 10.10.10.20    # WIN AD → harus GAGAL juga
```

> **Ini hasil yang BENAR dan diharapkan** — bukan bug. Kali di posisi WAN, dan pfSense secara default gak forward traffic dari WAN masuk ke LAN. Ini persis skenario "external attacker belum dapat foothold", yang nanti dibuka sedikit demi sedikit lewat firewall/NAT rule spesifik pas mulai lab attack (misal port-forward 80 ke DVWA untuk simulasi initial access).

---

## Troubleshooting

| Masalah | Kemungkinan Penyebab | Solusi |
|---------|----------------------|--------|
| Kali gak dapat IP sama sekali | VMnet0 Bridged salah arah adapter | Cek **Virtual Network Editor → VMnet0 → Bridged to** |
| Kali malah dapat IP `10.10.x.x` | Network adapter VM salah pilih (VMnet2/3, bukan Bridged) | Ganti VM Settings → Network Adapter → **Bridged** |
| Resolusi layar kecil / performance lambat | open-vm-tools belum terinstall | Ulangi Step 3 |
| Install lambat banget | Pilihan software terlalu banyak tools sekaligus | Untuk lab awal, cukup pilih **default tools** aja, tools tambahan bisa `apt install` manual nanti sesuai kebutuhan skenario |

---

## Catatan Keamanan Lab

Kali ini **attacker machine** — install tools sesuai kebutuhan skenario aja (gak perlu instal semua tools yang ada), biar VM tetap ringan. Karena posisinya di luar firewall (sama seperti M1/Dell), pastikan Kali cuma dipakai buat lab ini, jangan dipakai buat aktivitas lain di jaringan yang sama.
