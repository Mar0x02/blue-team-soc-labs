# WIN AD — Install Sysmon + Integrasi Wazuh

## Tujuan

Install **Sysmon** (Sysinternals) di WIN AD (`10.10.10.20`, Domain Controller `lab.local`) dan integrasikan log-nya ke Wazuh Agent yang udah terpasang, biar visibility jauh lebih detail dibanding Windows Event Log standar — penting buat DC karena ini target paling kritikal (DCSync, Golden Ticket, akses LSASS, lateral movement butuh data yang cuma Sysmon bisa kasih).

---

## Prerequisites

- WIN AD sudah punya **Wazuh Agent terinstall dan Active** (`WIN-AD-DC01` muncul Active di Wazuh Dashboard)
- Akses PowerShell **as Administrator** di WIN AD

---

## Step 1 — Download Sysmon + Config

```powershell
# Sysmon dari Sysinternals
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$env:TEMP\Sysmon.zip"
Expand-Archive -Path "$env:TEMP\Sysmon.zip" -DestinationPath "$env:TEMP\Sysmon" -Force

# Config SwiftOnSecurity (baseline paling umum, kompatibel sama kebanyakan Sigma rules)
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "$env:TEMP\sysmonconfig.xml"
```

> WIN AD Windows Server modern, jadi `Invoke-WebRequest` jalan normal — gak ada drama kayak Win7/WinXP.

---

## Step 2 — Install Sysmon dengan Config

```powershell
cd "$env:TEMP\Sysmon"
.\Sysmon64.exe -accepteula -i "$env:TEMP\sysmonconfig.xml"
```

---

## Step 3 — Verifikasi Sysmon Jalan

```powershell
Get-Service Sysmon64
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
```

---

## Step 4 — Integrasi ke Wazuh Agent

Buka `ossec.conf` pakai Notepad **as Administrator** (biar bisa save — file di `Program Files` butuh elevated privilege):

```powershell
notepad "C:\Program Files (x86)\ossec-agent\ossec.conf"
```

Tambahin block ini di dalam `<ossec_config>`:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Save, restart Wazuh Agent — nama service-nya `Wazuh` (bukan `WazuhSvc` kayak Win7):

```powershell
NET STOP Wazuh
NET START Wazuh
```

---

## Verifikasi

### Sysmon service & event lokal:

```powershell
Get-Service Sysmon64
# harus Running

Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
# harus ada event terbaru
```

### Wazuh Agent baca channel Sysmon tanpa error:

```powershell
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 20
```

### Log nyampe ke Wazuh Manager (dari Wazuh Dashboard → Discover):

Query pakai **DQL** (operator `and`, bukan `&&`):

```
agent.name: "WIN-AD-DC01" and data.win.system.channel: "Microsoft-Windows-Sysmon/Operational"
```

Kalau muncul hasil, chain lengkap **Sysmon → Windows Event Log → Wazuh Agent → Wazuh Manager → Dashboard** confirmed jalan.

![WIN AD Sysmon Log di Wazuh Dashboard](./asset/windows%20ad%20log.png)

---

## Catatan

- Config **SwiftOnSecurity** dipilih karena baseline paling umum dipakai komunitas dan paling banyak cocok sama Sigma rules dari `SigmaHQ/sigma` (salah satu RAG data source di project ini). Kalau ke depan butuh coverage lebih detail (misal fokus ke AD-specific technique), bisa dipertimbangkan ganti ke config **Olaf Hartong** yang lebih granular.
- Nama service Wazuh Agent **beda-beda per OS/instalasi** — WIN AD pakai `Wazuh`, Win7 pakai `WazuhSvc`, XP pakai `OssecSvc`. Selalu cek dulu pakai `Get-Service | Where-Object {$_.Name -like "*wazuh*"}` atau `*ossec*` kalau ragu sebelum `NET STOP`/`NET START`.
