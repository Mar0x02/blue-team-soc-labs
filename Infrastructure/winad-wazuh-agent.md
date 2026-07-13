# WIN AD — Install Wazuh Agent

## Tujuan

Install **Wazuh Agent 4.13** di WIN AD (`10.10.10.20`, Domain Controller `lab.local`) dan enroll ke **Wazuh Manager** di Dell (`192.168.43.x`, hotspot). Endpoint paling kritikal buat dimonitor — DC compromise itu game-over level di skenario attack.

Karena WIN AD Windows Server modern (2025), proses ini jauh lebih mulus dibanding Win7/WinXP — PowerShell-nya full support `Invoke-WebRequest`, gak ada isu TLS/root certificate.

---

## Prerequisites

- WIN AD sudah running sebagai DC `lab.local` — lihat [`winad-promotion.md`](./winad-promotion.md)
- Wazuh Manager di Dell sudah terinstall dan **service `wazuh-manager` running** — lihat [`wazuh-setup.md`](./wazuh-setup.md)
- Catat IP Dell yang aktif sekarang (`192.168.43.x`) — dinamis karena DHCP hotspot

---

## Step 1 — Deploy New Agent (dari Wazuh Dashboard)

1. Login Wazuh Dashboard (`https://<IP-Dell>`)
2. Menu **Agents** → **Deploy new agent**
3. **Select the package**: **Windows → MSI 32/64 bits**
4. **Server address**: IP Dell (`192.168.43.x`)
5. **Agent name**: `WIN-AD-DC01` (samain dengan computer name yang di-set di [`winad-setup.md`](./winad-setup.md))
6. Copy command PowerShell yang di-generate

---

## Step 2 — Install & Enroll

Jalankan command hasil generate wizard di **PowerShell as Administrator** (contoh, IP & versi menyesuaikan):

```powershell
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.13.1-1.msi -OutFile $env:tmp\wazuh-agent; msiexec.exe /i $env:tmp\wazuh-agent /q WAZUH_MANAGER='192.168.43.x' WAZUH_AGENT_NAME='WIN-AD-DC01'
```

---

## Step 3 — Start Service

Nama service Wazuh Agent di WIN AD adalah **`Wazuh`** (beda dari Win7 yang `WazuhSvc`):

```powershell
NET START Wazuh
```

---

## Verifikasi

### Dari WIN AD:

```powershell
Get-Content "C:\Program Files (x86)\ossec-agent\client.keys"
# harus ada 1 baris: 001 WIN-AD-DC01 <IP> <key>
```

### Dari Wazuh Dashboard:

**Agents** menu → cari `WIN-AD-DC01` → status harus **Active**.

---

## Catatan

- Nama service Wazuh Agent **beda-beda per instalasi/OS** — jangan asumsi sama kayak endpoint lain. Cek dulu pakai `Get-Service | Where-Object {$_.Name -like "*wazuh*"}` kalau ragu.
- Lanjutan: Sysmon + integrasi ke agent ini dibahas terpisah di [`winad-sysmon.md`](./winad-sysmon.md).
