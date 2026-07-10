# WIN AD Promotion — Active Directory Domain Services

## Tujuan

Promosikan VM **WIN AD** (`10.10.10.20`) jadi **Domain Controller** dengan install role AD DS + DNS Server, lalu buat domain forest baru buat lab. Domain ini nantinya jadi target lab lateral movement, Kerberoasting, Pass-the-Hash, dan Windows 7/XP di LAN2 bakal di-join ke domain ini.

- **Domain Name:** `lab.local`
- **NetBIOS Name:** `LAB`
- **Domain Controller:** `WIN-AD-DC01.lab.local` (`10.10.10.20`)

---

## Prerequisites

- WIN AD base OS + static IP `10.10.10.20/24` sudah terverifikasi — lihat [`winad-setup.md`](./winad-setup.md)
- Ping ke gateway (`10.10.10.1`) dan internet sudah OK
- Login sebagai `Administrator` (local admin, karena belum ada domain)

---

## Step 1 — Install Role AD DS + DNS Server

### Via Server Manager (GUI)

1. **Server Manager** → **Manage** → **Add Roles and Features**
2. **Before You Begin** → Next
3. **Installation Type:** Role-based or feature-based installation → Next
4. **Server Selection:** pilih server ini (`WIN-AD-DC01`) → Next
5. **Server Roles:** centang:
   - **Active Directory Domain Services**
   - **DNS Server**
   (akan muncul popup "Add features that are required" → klik **Add Features**)
6. Next → Next (Features, biarkan default) → Next (AD DS info) → Next (DNS Server info)
7. **Confirmation:** review → klik **Install**
8. Tunggu proses install selesai (~5-10 menit) → **Close** (jangan restart dulu, promosi dilakukan di step berikutnya tanpa restart manual)

### Via PowerShell (alternatif lebih cepat)

```powershell
Install-WindowsFeature -Name AD-Domain-Services, DNS -IncludeManagementTools
```

---

## Step 2 — Promosikan jadi Domain Controller

### Via Server Manager (GUI)

1. Setelah install role selesai, muncul notification flag (segitiga kuning) di Server Manager → klik **Promote this server to a domain controller**
2. **Deployment Configuration:** pilih **Add a new forest**
   - Root domain name: `lab.local`
3. **Domain Controller Options:**
   - Forest functional level: **Windows Server 2025** (aman karena cuma 1 DC di forest ini, gak ada rencana nambah DC versi lebih lama)
   - Domain functional level: **Windows Server 2025**
   - centang **Domain Name System (DNS) server** (biasanya udah tercentang)
   - **Directory Services Restore Mode (DSRM) password:** buat password kuat, **catat baik-baik** — ini password recovery kalau AD DS bermasalah
4. **DNS Options:** akan ada warning "A delegation for this DNS server cannot be created" — **abaikan**, ini normal untuk lab isolated (gak ada parent DNS zone di internet)
5. **Additional Options:**
   - NetBIOS domain name: `LAB` (otomatis ter-generate, biarkan default)
6. **Paths:** biarkan default (`C:\Windows\NTDS`, `C:\Windows\SYSVOL`)
7. **Review Options:** cek summary → Next
8. **Prerequisites Check:** akan ada beberapa warning (normal, misal soal DNS delegation) — pastikan gak ada **error** merah, cuma warning kuning masih aman → klik **Install**
9. VM akan **restart otomatis** setelah promosi selesai

### Via PowerShell (alternatif)

```powershell
Install-ADDSForest `
  -DomainName "lab.local" `
  -DomainNetbiosName "LAB" `
  -InstallDNS `
  -SafeModeAdministratorPassword (ConvertTo-SecureString "P@ssw0rdDSRM123!" -AsPlainText -Force) `
  -Force
```

---

## Step 3 — Update DNS Preferred (Setelah Restart)

Setelah restart dan login (sekarang login sebagai `LAB\Administrator`), update DNS preferred yang sempat pakai `8.8.8.8` di [`winad-setup.md`](./winad-setup.md) Step 4:

1. **Network Adapter Properties → IPv4 → Properties**
2. **Preferred DNS server:** `127.0.0.1`
3. **Alternate DNS server:** kosongkan, atau isi `8.8.8.8` sebagai forwarder cadangan (opsional)
4. **OK**

> **Catatan:** Kalau mau tetap bisa resolve domain internet (misal buat `apt`/Windows Update di VM lain lewat DNS ini nanti), configure **DNS Forwarder** di DNS Manager (Step 5) daripada isi Alternate DNS server manual — lebih rapi dan konsisten.

---

## Step 4 — Verifikasi AD DS

### Cek status Domain Controller:

```powershell
dcdiag /v
```

Pastikan mayoritas test **passed**, terutama: `Advertising`, `FrsEvent`, `NetLogons`, `Services`, `SystemLog`.

### Cek DNS resolution domain:

```powershell
nslookup lab.local
# harus resolve ke 10.10.10.20

nslookup WIN-AD-DC01.lab.local
```

### Cek dari VM lain di LAN1 (misal Web-Server):

```bash
# Set DNS server sementara ke WIN AD buat test (opsional, gak permanen)
nslookup lab.local 10.10.10.20
```

### Buka Active Directory Users and Computers:

**Server Manager → Tools → Active Directory Users and Computers** — pastikan domain `lab.local` muncul dengan struktur default (Builtin, Computers, Domain Controllers, Users).

---

## Step 5 — Konfigurasi DNS Forwarder (Opsional, Recommended)

Biar VM yang nanti join domain tetap bisa resolve internet lewat DNS server ini:

1. **Server Manager → Tools → DNS**
2. Klik kanan nama server (`WIN-AD-DC01`) → **Properties**
3. Tab **Forwarders** → **Edit**
4. Tambahkan: `8.8.8.8`, `1.1.1.1`
5. **OK**

---

## Step 6 — Buat Struktur OU, User, dan Group Dasar

Buat struktur dasar biar simulasi environment enterprise lebih realistis (dipakai nanti buat skenario lateral movement, Kerberoasting, dll):

```powershell
# Buat OU
New-ADOrganizationalUnit -Name "Lab-Users" -Path "DC=lab,DC=local"
New-ADOrganizationalUnit -Name "Lab-Computers" -Path "DC=lab,DC=local"
New-ADOrganizationalUnit -Name "Lab-Servers" -Path "DC=lab,DC=local"

# Buat contoh user
New-ADUser -Name "PC Analyst" -SamAccountName "p.analyst" `
  -UserPrincipalName "p.analyst@lab.local" `
  -Path "OU=Lab-Users,DC=lab,DC=local" `
  -AccountPassword (ConvertTo-SecureString "PasswordPc123!" -AsPlainText -Force) `
  -Enabled $true

New-ADUser -Name "Service Account" -SamAccountName "svc-web" `
  -UserPrincipalName "svc-web@lab.local" `
  -Path "OU=Lab-Users,DC=lab,DC=local" `
  -AccountPassword (ConvertTo-SecureString "PasswordSvc123!" -AsPlainText -Force) `
  -Enabled $true

# Buat group
New-ADGroup -Name "IT-Support" -GroupScope Global -Path "OU=Lab-Users,DC=lab,DC=local"
Add-ADGroupMember -Identity "IT-Support" -Members "p.analyst"
```

> **Catatan:** User `svc-web` dengan SPN nanti bisa dipakai buat demo **Kerberoasting** — akan dikonfigurasi lebih detail pas masuk writeup lab attack spesifik.

---

## Troubleshooting

| Masalah | Kemungkinan Penyebab | Solusi |
|---------|----------------------|--------|
| Promosi gagal di Prerequisites Check (error, bukan warning) | Static IP belum fix, atau ada DC lain dengan nama sama di jaringan | Pastikan `ipconfig` static `10.10.10.20`, restart dan ulangi |
| `dcdiag` ada test **failed** | Servis AD DS/DNS belum fully started setelah restart | Tunggu beberapa menit, restart servis: `Restart-Service NTDS, DNS` |
| Tidak bisa akses internet setelah DNS diganti `127.0.0.1` | DNS Forwarder belum dikonfigurasi | Ulangi Step 5 |
| `New-ADUser` error "path does not exist" | OU belum dibuat / typo di `-Path` | Cek ulang OU dengan `Get-ADOrganizationalUnit -Filter *` |
