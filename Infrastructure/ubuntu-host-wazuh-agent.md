# Ubuntu Host — Install Wazuh Agent

## Tujuan

Install **Wazuh Agent 4.13** di Ubuntu Host (`10.10.20.30`, LAN2) dan enroll ke **Wazuh Manager** di Dell (`192.168.43.x`, hotspot) — endpoint pertama yang termonitor SIEM, jadi template alur buat 4 endpoint lain (Web-Server, WIN AD, Win7, WinXP).

Koneksi agent → manager arahnya **LAN2 → hotspot** (Ubuntu Host initiate koneksi keluar ke Dell) — beda arah sama kasus DVWA↔Kali kemarin, jadi gak butuh NAT/port-forward tambahan di pfSense. Outbound NAT yang udah aktif (kebukti dari `ping 8.8.8.8` yang berhasil di semua victim VM) udah cukup buat Ubuntu Host nyampe ke Dell.

---

## Prerequisites

- Ubuntu Host base OS + static IP `10.10.20.30/24` sudah terverifikasi — lihat [`ubuntu-host-setup.md`](./ubuntu-host-setup.md)
- Wazuh Manager di Dell sudah terinstall dan **service `wazuh-manager` running** — lihat [`wazuh-setup.md`](./wazuh-setup.md)
- **WIN AD harus nyala juga** kalau Ubuntu Host udah domain-joined — DNS Ubuntu Host diarahin cuma ke WIN AD (`10.10.10.20`), jadi kalau WIN AD mati, resolusi internet (`packages.wazuh.com`) ikut mati. Lihat [`ubuntu-host-domain-join.md`](./ubuntu-host-domain-join.md) Step 2
- Catat IP Dell yang aktif sekarang (`ip a | grep "inet 192.168"` di Dell) — dinamis karena DHCP hotspot
- User dengan akses `sudo` di Ubuntu Host (user lokal `victim`, **bukan** user domain — lihat gotcha di Step 3)

---

## Step 1 — Pastikan Wazuh Manager di Dell Running

```bash
sudo systemctl status wazuh-manager
sudo /var/ossec/bin/wazuh-control status
```

Semua daemon (`wazuh-modulesd`, `wazuh-remoted`, `wazuh-analysisd`, dll) harus `running`. Kalau ada yang `stopped`, restart manager dan tunggu ~10 detik:

```bash
sudo systemctl restart wazuh-manager
```

---

## Step 2 — Deploy New Agent (dari Wazuh Dashboard)

1. Login Wazuh Dashboard (`https://<IP-Dell>`)
2. Menu **Agents** → **Deploy new agent**
3. **Select the package**: pilih **Linux → DEB amd64** (Ubuntu 64-bit)
4. **Server address**: isi IP Dell (`192.168.43.x`)
5. **Agent name**: `ubuntu-victim` (samain dengan hostname yang di-set waktu install OS — lihat `ubuntu-host-setup.md` Step 2)
6. Dashboard otomatis generate command install + enroll di step berikutnya — copy command itu

---

## Step 3 — Install Agent di Ubuntu Host

Jalankan command hasil generate dari wizard (contoh, IP & versi menyesuaikan):

```bash
wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.13.1-1_amd64.deb && sudo WAZUH_MANAGER='192.168.43.130' WAZUH_AGENT_NAME='ubuntu-victim' dpkg -i ./wazuh-agent_4.13.1-1_amd64.deb
```

> **Gotcha — jalankan sebagai user lokal, bukan user domain:** Kalau Ubuntu Host udah domain-joined (`ubuntu-host-domain-join.md`), user domain (misal `p.analyst@lab.local`) **default-nya gak punya akses `sudo`** setelah `realm join`. Login/`sudo -i` pakai user lokal (`victim`) buat jalanin command ini, atau tambahin user domain ke grup `sudo` dulu (`sudo usermod -aG sudo p.analyst@lab.local`) kalau emang mau tes pakai domain user.

---

## Step 4 — Start Agent

```bash
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
sudo systemctl status wazuh-agent
```

---

## Verifikasi

### Dari Ubuntu Host:

```bash
sudo systemctl status wazuh-agent
# harus active (running)

sudo tail -n 20 /var/ossec/logs/ossec.log
# cari baris "Connected to the server" atau sejenisnya
```

### Dari Wazuh Dashboard:

**Agents** menu → cari `ubuntu-victim` → status harus **Active** (bukan **Never connected** atau **Disconnected**).

---

## Troubleshooting

| Masalah | Kemungkinan Penyebab | Solusi |
|---------|----------------------|--------|
| Dashboard error `3099 - Some Wazuh daemons are not ready yet (wazuh-modulesd->stopped, wazuh-remoted->stopped)` | `wazuh-manager` di Dell belum fully up (baru boot, atau crash) | Lihat Step 1, `sudo systemctl restart wazuh-manager`, cek `/var/ossec/logs/ossec.log` di Dell kalau masih gagal |
| `dpkg -i` gagal, `p.analyst is not in the sudoers file` | Login pakai user domain yang belum punya akses sudo | Lihat gotcha di Step 3 — pakai user lokal `victim`, atau tambahin domain user ke grup `sudo` |
| `wget` gagal resolve `packages.wazuh.com` | DNS Ubuntu Host cuma ke WIN AD dan WIN AD lagi mati | Nyalain WIN AD (lihat Prerequisites), atau switch DNS sementara ke `8.8.8.8` |
| Agent status **Never connected** di dashboard | IP Dell yang dipakai pas install (`WAZUH_MANAGER`) udah beda dari IP Dell sekarang (DHCP hotspot berubah) | Cek IP Dell terbaru, update `<address>` di `/var/ossec/etc/ossec.conf` Ubuntu Host, restart `wazuh-agent` |
| Agent status **Disconnected** setelah tadinya Active | pfSense/Dell/Ubuntu Host mati atau network putus sementara | Cek semua VM/device nyala, cek konektivitas dasar (`ping` ke IP Dell dari Ubuntu Host) |

---

## Catatan Keamanan Lab

Enrollment ini pakai koneksi non-TLS-verified default (agent-manager pairing lewat `WAZUH_MANAGER` env var, bukan lewat `agent-auth` dengan password terpisah) — cukup buat lab, tapi di environment production biasanya dikombinasikan sama **agent enrollment password** (`authd.pass`) biar gak sembarang device bisa self-enroll ke manager.
