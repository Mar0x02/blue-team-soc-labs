# Windows XP — Install Wazuh Agent

## Tujuan

Install Wazuh Agent di Windows XP (`10.10.20.20`, LAN2), enroll ke Wazuh Manager di Dell (`192.168.43.x`). Endpoint legacy terakhir dari 3 victim workstation LAN2 (nyusul Ubuntu Host & Win7).

XP ini emang ribet dari sononya — browser-nya kejadul buat HTTPS modern, gak ada PowerShell sama sekali (beda dari Win7 yang minimal masih punya PS 2.0), dan certificate store-nya udah gak dapet update dari 2014. Jadi alurnya lebih banyak akal-akalan dibanding Win7.

---

## Prerequisites

- Win7 base OS udah domain-joined dan reachable di `10.10.20.10` — dipakai sebagai perantara transfer file (satu subnet LAN2, gak kena firewall)
- Wazuh Manager di Dell running
- Login pakai `LAB\Administrator` (lupa password local Administrator XP, udah pernah di-reset — lihat kasus serupa di Win7)

---

## Step 1 — Download MSI, Transfer Lewat Win7

XP gak bisa download langsung dari `packages.wazuh.com` (browser-nya gak support TLS modern), jadi:

1. File MSI Wazuh Agent yang udah didownload buat Win7 kemarin, taruh di folder yang di-share
2. Di Win7: klik kanan folder yang isi file MSI → **Sharing** → share ke network
3. Di XP: buka **My Computer**, akses `\\10.10.20.10\nama-share` (langsung reachable, XP dan Win7 satu subnet LAN2, gak perlu lewat firewall rule apapun)
4. Copy file MSI-nya ke lokal XP (Desktop aja biar gampang)

---

## Step 2 — Install via GUI Installer

Double-click MSI-nya, install seperti biasa (next-next-finish). Selesai instalasi, ada opsi buka **wazuh-agent.exe** config tool — coba isi Manager IP di situ dulu.

**Kemungkinan besar gagal save**, muncul pesan kayak gini:

```
The Dynamic signature validation is not available because the CA name
('DigiCert Assured ID Root CA') is not available.
```

Ini bukan error fatal — cuma XP gak punya root certificate modern (gak pernah update sejak EOL 2014), jadi Windows gak bisa verifikasi digital signature tool-nya, dan tool-nya nolak nyimpen setting. Gak usah dipaksain fix (install root cert manual ribet dan gak worth buat 1 VM lab) — langsung ke Step 3.

---

## Step 3 — Edit ossec.conf Manual

1. Buka `C:\Program Files\ossec-agent\ossec.conf` pakai Notepad (di XP path-nya `Program Files` doang, bukan `Program Files (x86)`)
2. Cari block:
   ```xml
   <client>
     <server>
       <address>MANAGER_IP</address>
       <port>1514</port>
       <protocol>tcp</protocol>
     </server>
   </client>
   ```
3. Ganti `MANAGER_IP` jadi IP Dell
4. Save

Gak perlu tambahin block `<enrollment>` apapun — biarin default, nanti auto-enroll pakai computer name XP (`winxp-ef16ad5b7`, sesuai yang di-set di `winxp-setup.md`).

---

## Step 4 — Restart Service

Cek dulu nama service-nya di **Control Panel → Administrative Tools → Services** — di XP kemungkinan masih nama lama `OssecSvc`, bukan `WazuhSvc` kayak Win7:

```cmd
net stop OssecSvc
net start OssecSvc
```

---

## Verifikasi

Cek `client.keys` udah keisi:

```cmd
type C:\Program Files\ossec-agent\client.keys
```

Terus cek di Wazuh Dashboard — `winxp-ef16ad5b7` harus muncul status **Active**.

---

## Catatan

- Status agent di dashboard **gak instan** update pas VM dimatiin — Wazuh Manager pakai keepalive, default ~10 menit baru pindah ke status **Disconnected** setelah agent beneran mati.
- 3 endpoint LAN2 (Ubuntu Host, Win7, WinXP) sekarang semua udah punya agent — tinggal Web-Server dan WIN AD di LAN1.
