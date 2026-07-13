# Windows 7 — Install Wazuh Agent

## Tujuan

Install **Wazuh Agent 4.13** di Windows 7 (`10.10.20.10`, LAN2) dan enroll ke **Wazuh Manager** di Dell (`192.168.43.x`, hotspot) — endpoint kedua setelah Ubuntu Host, sekaligus endpoint Windows pertama.

Sama seperti Ubuntu Host, koneksi agent → manager arahnya **LAN2 → hotspot** (Win7 initiate koneksi keluar), jadi gak butuh NAT/port-forward tambahan di pfSense — outbound NAT yang udah aktif cukup.

---

## Prerequisites

- Win7 base OS + static IP `10.10.20.10/24` sudah terverifikasi — lihat [`win7-setup.md`](./win7-setup.md)
- Wazuh Manager di Dell sudah terinstall dan **service `wazuh-manager` running** — lihat [`wazuh-setup.md`](./wazuh-setup.md)
- Catat IP Dell yang aktif sekarang (`192.168.43.x`) — dinamis karena DHCP hotspot
- Akses admin di Win7 — kalau lupa password `Administrator` lokal, reset via `LAB\Administrator` (lihat catatan di `win7-passwords.txt`) atau login pakai domain user yang di-add ke local Administrators

> **Catatan penting:** Win7 default cuma punya **PowerShell 2.0**, yang **gak support `Invoke-WebRequest`** (baru ada dari PowerShell 3.0). Jadi command generate dari Wazuh Dashboard deploy wizard (yang pakai `Invoke-WebRequest`) **gak bisa langsung dipakai** — perlu pendekatan manual (lihat Step 2).

---

## Step 1 — Deploy New Agent (dari Wazuh Dashboard)

1. Login Wazuh Dashboard (`https://<IP-Dell>`)
2. Menu **Agents** → **Deploy new agent**
3. **Select the package**: pilih **Windows → MSI 32/64 bits** (installer universal, cocok buat Win7 32-bit)
4. **Server address**: isi IP Dell (`192.168.43.x`)
5. **Agent name**: `WIN7-VICTIM` (samain dengan computer name yang di-set waktu install OS — lihat `win7-setup.md` Step 2)
6. Dashboard generate command PowerShell — **jangan langsung dipakai** kalau Win7 masih PowerShell 2.0, lihat Step 2

---

## Step 2 — Download MSI Secara Manual

Karena `Invoke-WebRequest` gak jalan di PowerShell 2.0, download file MSI-nya manual (browser di Win7, atau transfer file dari device lain):

```
https://packages.wazuh.com/4.x/windows/wazuh-agent-4.13.1-1.msi
```

Simpan di lokasi yang gampang diakses, misal `C:\Users\Administrator\Downloads\`.

---

## Step 3 — Install via GUI Installer

1. Double-click file MSI yang udah didownload
2. Ikuti wizard instalasi (default)
3. Di layar terakhir installer, **centang opsi buka `wazuh-agent.exe`** (config utility bawaan) setelah instalasi selesai
4. Config utility bakal muncul — isi **Manager IP** dengan IP Dell (`192.168.43.x`)
5. Save/Apply

> Agent otomatis auto-enroll pakai **computer name Windows** (`WIN7-VICTIM`) sebagai nama agent — gak perlu edit `ossec.conf` manual buat set nama, karena computer name-nya udah cocok sama convention yang kita mau sejak awal install OS.

---

## Step 4 — Start Service (kalau belum otomatis jalan)

```powershell
NET START WazuhSvc
```

---

## Verifikasi

### Dari Win7 (PowerShell atau Command Prompt):

```powershell
Get-Content "C:\Program Files (x86)\ossec-agent\client.keys"
# harus ada 1 baris: 001 WIN7-VICTIM <IP> <key>
```

### Dari Wazuh Dashboard:

**Agents** menu → cari `WIN7-VICTIM` → status harus **Active**.

---

## Troubleshooting

| Masalah | Kemungkinan Penyebab | Solusi |
|---------|----------------------|--------|
| `Invoke-WebRequest` : command not found (padahal udah di PowerShell) | Win7 default PowerShell 2.0, `Invoke-WebRequest` baru ada di 3.0+ | Cek versi: `$PSVersionTable.PSVersion` → kalau `Major` = 2, download manual (Step 2), skip command generate dari wizard |
| `msiexec /q` gagal / `dpkg`-setara di Windows gak jalan | PowerShell dibuka biasa, bukan **Run as administrator** | Buka ulang PowerShell/Command Prompt lewat **Run as administrator** |
| `NET START WazuhSvc` → "The Wazuh service could not be started. The service did not report an error." | Error generik, gak jelas akar masalahnya | Cek log: `Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 30` |
| Log muncul `Invalid element in the configuration 'enrollment'` / `No Client configured` setelah edit manual `ossec.conf` | Typo atau nesting XML salah pas nambahin block `<enrollment>` manual | Kalau ragu edit XML manual, **skip aja** — pakai config utility bawaan installer (Step 3) yang auto-enroll pakai computer name, jauh lebih aman daripada edit `ossec.conf` manual |
| Lupa password `Administrator` lokal Win7 | Gak pernah dicatat waktu install OS | Reset via `LAB\Administrator` (Computer Management → Local Users and Groups → Set Password) — lihat `win7-passwords.txt` |

---

## Catatan Keamanan Lab

Sama kayak agent Ubuntu Host, enrollment ini pakai auto-enroll standar (bukan `agent-auth` dengan password enrollment terpisah) — cukup buat lab. Password local Administrator Win7 udah di-reset dan dicatat di `win7-passwords.txt` (gitignored) karena yang lama lupa — kalau ke depan ada VM lain yang perlu credential serupa, selalu catat langsung ke file `-passwords.txt` masing-masing biar gak kejadian lagi.
