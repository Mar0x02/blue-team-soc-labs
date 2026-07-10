# Windows XP — Join Domain lab.local

## Tujuan

Join VM Windows XP (`10.10.20.20`, LAN2) ke domain `lab.local` di WIN AD (`10.10.10.20`, Windows Server 2025). XP itu OS 2001 yang cuma bicara protokol lama (SMBv1, NTLMv1/LM), sementara WIN AD adalah DC modern yang default-nya lebih strict — **butuh 2 penyesuaian kompatibilitas di WIN AD** (SMBv1 + NTLM level) sebelum join bisa berhasil. Sudah diverifikasi jalan di lab ini.

---

## Prerequisites

- Windows XP base OS + static IP `10.10.20.20/24` sudah terverifikasi — lihat [`winxp-setup.md`](./winxp-setup.md)
- Firewall rule `Allow LAN2 to WIN AD` di pfSense **sudah ada** dari proses join Windows 7 — lihat [`win7-domain-join.md`](./win7-domain-join.md) Step 1. Rule ini scoped ke **LAN2 net → `10.10.10.20`**, jadi otomatis berlaku juga untuk XP (`10.10.20.20`), gak perlu bikin rule baru.
- Windows Firewall WIN AD sudah di-disable — lihat troubleshooting `win7-domain-join.md`

---

## Step 1 — Ganti DNS di Windows XP ke WIN AD

1. **Control Panel → Network Connections** → klik kanan **Local Area Connection → Properties**
2. **Internet Protocol (TCP/IP) → Properties**
3. Ganti:

```
Preferred DNS server : 10.10.10.20
Alternate DNS server  : (kosongkan)
```

4. **OK → OK**

---

## Step 2 — Sync Waktu ke WIN AD

Sama seperti Windows 7, clock skew >5 menit bikin Kerberos gagal:

```cmd
net time \\10.10.10.20 /set /y
```

Verifikasi konektivitas dasar:

```cmd
ping 10.10.10.20
nslookup lab.local
```

---

## Step 3 — Fix Kompatibilitas di WIN AD (Wajib, Lakukan Dulu Sebelum Join)

Dua penyesuaian ini **wajib** dilakukan di WIN AD dulu — kalau di-skip, proses join di Step 4 bakal gagal dengan error `The specified network name is no longer available`.

### A. Enable SMBv1 Server Feature

Windows Server 2025 gak install SMBv1 sama sekali secara default. XP cuma bisa SMBv1 buat akses share SYSVOL/NETLOGON yang dibutuhkan proses join & Group Policy.

**Lewat PowerShell (WIN AD, run as Administrator):**

```powershell
# Install feature dulu (kalau belum ada, cmdlet Set-SmbServerConfiguration bakal error "service does not exist")
Install-WindowsFeature FS-SMB1

# Restart kalau diminta
Restart-Computer

# Setelah restart, enable protocol-nya
Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force

# Restart service biar langsung aktif
Restart-Service LanmanServer -Force
```

**Atau lewat GUI:** **Server Manager → Add Roles and Features → Features** → centang **SMB 1.0/CIFS File Sharing Support** (dan semua sub-item) → Install → restart kalau diminta.

Verifikasi:

```powershell
Get-SmbServerConfiguration | Select EnableSMB1Protocol
# harus True
```

> **Catatan keamanan:** SMBv1 punya banyak CVE terkenal (termasuk EternalBlue/MS17-010 yang justru mau kita simulasikan!). Aktifin ini cuma karena kebutuhan kompatibilitas legacy lab yang terisolasi — jangan pernah aktifin SMBv1 di jaringan nyata.

### B. Longgarkan NTLM Authentication Level

WIN AD default nolak response NTLMv1/LM yang dikirim XP.

```powershell
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 2 -Type DWord
```

> Alternatif GUI: **Local Security Policy (`secpol.msc`) → Local Policies → Security Options → Network security: LAN Manager authentication level** → set ke **Send LM & NTLM - use NTLMv2 session security if negotiated**.

> Ini gak ngaruh ke Windows 7 atau client lain — settingan ini cuma **melonggarkan minimum yang diterima** DC, client yang udah kirim NTLMv2/Kerberos (kayak Win7) tetap pakai cara mereka masing-masing, gak ke-downgrade paksa.

---

## Step 4 — Join Domain

1. Klik kanan **My Computer → Properties**
2. Tab **Computer Name** → klik **Change**
3. Pilih **Domain**, isi: `lab.local`
4. **OK** → muncul prompt kredensial:
   ```
   Username: Administrator
   Password: (lihat winad-passwords.txt)
   ```
5. Tunggu proses join → restart saat diminta

---

## Kalau Masih Gagal Setelah Fix A & B

Kemungkinan kecil masih ada masalah LDAP signing/channel binding (kalau error eksplisit nyebut LDAP atau secure channel). Longgarkan lewat registry `LDAPServerIntegrity` (set ke `1` = None instead of `2` = Require signing) di `HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters`.

Kalau tetap gagal total, XP dibiarkan **workgroup-only** — tetap valid sebagai simulasi legacy device yang gak terintegrasi domain (skenario umum di enterprise nyata: mesin lawas yang gak pernah di-upgrade karena aplikasi legacy yang butuh XP).

---

## Verifikasi

Dari Windows XP setelah restart & login domain (format login: `LAB\username`):

```cmd
echo %USERDOMAIN%\%USERNAME%
```

> **Catatan:** `whoami` gak tersedia built-in di Windows XP (baru ada default sejak Vista/Server 2008 ke atas) — pakai `echo %USERDOMAIN%\%USERNAME%` sebagai gantinya.

Harus muncul `LAB\<username>` sesuai akun yang dipakai login.

Dari WIN AD:

```powershell
Get-ADComputer -Filter * | Select Name, DistinguishedName
```

Harus muncul `WINXP-VICTIM`.
