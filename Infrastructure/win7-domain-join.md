# Windows 7 — Join Domain lab.local

## Tujuan

Join VM Windows 7 (`10.10.20.10`, LAN2) ke domain `lab.local` yang di-host WIN AD (`10.10.10.20`, LAN1). Karena LAN1 dan LAN2 di-isolasi firewall by default (lihat [`pfsense-setup.md`](./pfsense-setup.md) Step 6.5), perlu firewall rule tambahan yang **scoped khusus ke WIN AD** — bukan buka seluruh LAN1, biar isolasi LAN1↔LAN2 tetap terjaga untuk host lain.

---

## Prerequisites

- Windows 7 base OS + static IP `10.10.20.10/24` sudah terverifikasi — lihat [`win7-setup.md`](./win7-setup.md)
- WIN AD sudah promosi jadi Domain Controller `lab.local` — lihat [`winad-promotion.md`](./winad-promotion.md)
- Kredensial domain admin (`Administrator` / lihat `winad-passwords.txt`)

---

## Step 1 — Tambah Firewall Rule di pfSense (LAN2 → WIN AD saja)

Rule ini **scoped ke satu host** (`10.10.10.20`), bukan buka semua LAN1 — jadi Web-Server (`10.10.10.10`) tetap gak reachable dari LAN2.

1. Login Web GUI pfSense (`https://10.10.10.1`)
2. **Firewall → Rules → LAN2**
3. Klik **Add** (panah atas — biar rule ini diproses SEBELUM rule block LAN2→LAN1 yang sudah ada)
4. Isi:
   - Action: **Pass**
   - Interface: LAN2
   - Protocol: **Any**
   - Source: **LAN2 net**
   - Destination: **Single host** → `10.10.10.20`
   - Description: `Allow LAN2 to WIN AD (domain join & auth)`
5. **Save → Apply Changes**
6. Pastikan urutan rule: **rule ini di ATAS** rule "Block LAN2 to LAN1" — kalau rule block ada di atas, rule allow ini gak akan pernah kena (pfSense proses top-down, rule pertama yang match yang menang)

> **Kenapa "Any" protocol, bukan port spesifik?** Domain join butuh banyak port sekaligus: DNS (53), Kerberos (88), LDAP (389), SMB (445), RPC Endpoint Mapper (135) + dynamic RPC ports, NTP (123), Global Catalog (3268). Daripada rawan miss satu port dan susah di-debug, untuk lab kita izinkan semua protokol ke host itu — tetap aman karena discope ke 1 IP tujuan doang, bukan seluruh LAN1.

---

## Step 2 — Ganti DNS di Windows 7 ke WIN AD

1. **Control Panel → Network and Sharing Center → Change adapter settings**
2. Klik kanan **Local Area Connection → Properties**
3. **Internet Protocol Version 4 (TCP/IPv4) → Properties**
4. Ganti:

```
Preferred DNS server : 10.10.10.20
Alternate DNS server  : (kosongkan, atau 8.8.8.8 kalau mau tetap resolve internet — lihat catatan)
```

> **Catatan:** WIN AD udah dikonfigurasi DNS Forwarder ke `8.8.8.8`/`1.1.1.1` (lihat `winad-promotion.md` Step 5), jadi kalaupun Alternate DNS dikosongkan, resolusi internet tetap jalan lewat forwarder WIN AD. Lebih rapi kosongkan Alternate biar semua query DNS konsisten lewat satu path (WIN AD).

5. **OK → Close**

---

## Step 3 — Verifikasi Konektivitas ke WIN AD

Dari Command Prompt Windows 7:

```cmd
ping 10.10.10.20
nslookup lab.local
```

`nslookup lab.local` harus resolve ke `10.10.10.20`. Kalau gagal, cek ulang Step 1 (firewall rule) dan Step 2 (DNS).

---

## Step 4 — Join Domain

1. **Control Panel → System → Change settings** (atau klik kanan **Computer → Properties → Change settings**)
2. Tab **Computer Name** → klik **Change...**
3. Pilih **Domain**, isi: `lab.local`
4. **OK** → muncul prompt kredensial:
   ```
   Username: Administrator     (atau LAB\Administrator)
   Password: (lihat winad-passwords.txt)
   ```
5. Tunggu — kalau berhasil muncul dialog **"Welcome to the lab.local domain"**
6. **OK** → muncul prompt **restart required** → **Restart Now**

---

## Step 5 — Login dengan Domain Account

Setelah restart, di login screen:

1. Klik **Switch User** → **Other User**
2. Login dengan format: `LAB\p.analyst` (atau `LAB\Administrator` untuk testing awal)
3. Masukkan password sesuai `winad-passwords.txt`

---

## Verifikasi

### Dari Windows 7 (setelah login domain):

```cmd
whoami
# harus muncul: lab\p.analyst (atau user domain yang dipakai login)

gpresult /r
# cek domain & OU yang berlaku
```

### Dari WIN AD (PowerShell):

```powershell
Get-ADComputer -Filter * | Select Name, DistinguishedName
```

Harus muncul `WIN7-VICTIM` di list — defaultnya masuk container **Computers** (bukan OU `Lab-Computers` yang kita buat, karena join domain default masuk ke default container).

### (Opsional) Pindahkan computer object ke OU `Lab-Computers`:

```powershell
Get-ADComputer -Identity "WIN7-VICTIM" | Move-ADObject -TargetPath "OU=Lab-Computers,DC=lab,DC=local"
```

![Windows 7 Domain Join Done](./asset/windows%207%20ad.png)

---

## Troubleshooting

| Masalah | Kemungkinan Penyebab | Solusi |
|---------|----------------------|--------|
| "Domain not found" / "The specified domain either does not exist..." | DNS belum diarahkan ke `10.10.10.20`, atau firewall rule belum aktif | Ulangi Step 1 & Step 2, cek `nslookup lab.local` |
| Prompt kredensial ditolak terus | Salah format username/password | Coba format `LAB\Administrator` (bukan cuma `Administrator`), cocokkan password di `winad-passwords.txt` |
| Join berhasil tapi lambat banget (timeout beberapa kali) | Firewall rule "Any protocol" ke `10.10.10.20` mungkin ke-block rule lain di atasnya | Cek urutan rule di **Firewall → Rules → LAN2**, pastikan rule allow ini di atas rule block |
| Login domain user gagal setelah restart | Rule firewall LAN2→WIN AD keburu ke-disable, atau login pakai format salah | Cek rule masih aktif di pfSense, pastikan format login `LAB\username` |

---

## Catatan Keamanan Lab

Rule firewall `Allow LAN2 to WIN AD` ini **permanen aktif** (bukan cuma buat proses join sekali doang) — karena domain-joined machine emang perlu terus-menerus komunikasi ke DC (Kerberos ticket renewal, Group Policy refresh, logon authentication). Ini realistis dengan kondisi enterprise beneran, di mana workstation selalu perlu jalur ke DC meskipun network tersegmentasi.
