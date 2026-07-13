# Web-Server — Install Wazuh Agent

## Tujuan

Install **Wazuh Agent 4.13** di Web-Server (`10.10.10.10`, LAN1) dan enroll ke **Wazuh Manager** di Dell (`192.168.43.x`, hotspot) — endpoint terakhir dari 5 target victim, sekaligus paling penting karena ini host DVWA (target attack utama).

Sama seperti Ubuntu Host, koneksi agent → manager arahnya **LAN1 → hotspot** (Web-Server initiate koneksi keluar), jadi gak butuh NAT/port-forward tambahan — outbound NAT pfSense yang udah aktif cukup.

---

## Prerequisites

- Web-Server base OS + DVWA sudah terinstall — lihat [`web-server-setup.md`](./web-server-setup.md) dan [`dvwa-setup.md`](./dvwa-setup.md)
- Wazuh Manager di Dell sudah terinstall dan **service `wazuh-manager` running** — lihat [`wazuh-setup.md`](./wazuh-setup.md)
- Catat IP Dell yang aktif sekarang (`192.168.43.x`) — dinamis karena DHCP hotspot

---

## Step 1 — Deploy New Agent (dari Wazuh Dashboard)

1. Login Wazuh Dashboard (`https://<IP-Dell>`)
2. Menu **Agents** → **Deploy new agent**
3. **Select the package**: **Linux → DEB amd64**
4. **Server address**: IP Dell (`192.168.43.x`)
5. **Agent name**: `web-server` (sesuai hostname di `web-server-setup.md`)
6. Copy command hasil generate

---

## Step 2 — Install Agent

```bash
wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.13.1-1_amd64.deb && sudo WAZUH_MANAGER='192.168.43.130' WAZUH_AGENT_NAME='web-server' dpkg -i ./wazuh-agent_4.13.1-1_amd64.deb
```

> **Gotcha:** Command generate dari dashboard itu **case/karakter-sensitive** — salah ketik dikit di URL (misal ada extra/kurang karakter) bisa balikin `403 Forbidden` dari CDN Wazuh, bukan `404`, jadi errornya nyasar keliatan kayak masalah akses padahal cuma typo. Kalau ketemu `403 Forbidden`, cek dulu ulang command-nya diketik/di-paste persis sama kayak yang di-generate dashboard sebelum coba alternatif lain.
>
> Kalau masih gagal juga setelah dipastiin gak ada typo, pakai jalur repo APT resmi (lebih robust, gak hardcode nama file versi spesifik):
> ```bash
> curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
> sudo chmod 644 /usr/share/keyrings/wazuh.gpg
> echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
> sudo apt update
> sudo WAZUH_MANAGER='192.168.43.130' WAZUH_AGENT_NAME='web-server' apt install -y wazuh-agent
> ```

---

## Step 3 — Start Agent

```bash
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
sudo systemctl status wazuh-agent
```

---

## Verifikasi

### Dari Web-Server:

```bash
sudo systemctl status wazuh-agent
# harus active (running)
```

### Dari Wazuh Dashboard:

**Agents** menu → cari `web-server` → status harus **Active**.

---

## Catatan

Dengan ini, semua 5 endpoint victim udah termonitor Wazuh: **Ubuntu Host, Win7, WinXP, WIN AD, Web-Server**. Tinggal pfSense yang beda mekanisme (syslog forwarding, bukan agent) — dibahas terpisah.
