# Ubuntu Host — Join Domain lab.local

## Tujuan

Join VM Ubuntu Host (`10.10.20.30`, LAN2) ke domain `lab.local` yang di-host WIN AD (`10.10.10.20`, LAN1), pakai **`realmd` + `sssd`** (cara modern untuk domain-join Linux ke AD, gantiin `winbind` yang lebih lawas).

Firewall rule `Allow LAN2 to WIN AD` yang dibuat waktu [`win7-domain-join.md`](./win7-domain-join.md) Step 1 source-nya **`LAN2 net`** (bukan scoped ke satu host LAN2 doang) — jadi rule itu udah otomatis cover Ubuntu Host juga, gak perlu bikin rule baru.

---

## Prerequisites

- Ubuntu Host base OS + static IP `10.10.20.30/24` sudah terverifikasi — lihat [`ubuntu-host-setup.md`](./ubuntu-host-setup.md)
- WIN AD sudah promosi jadi Domain Controller `lab.local` — lihat [`winad-promotion.md`](./winad-promotion.md)
- Firewall rule `Allow LAN2 to WIN AD` sudah aktif — lihat [`win7-domain-join.md`](./win7-domain-join.md) Step 1 (cek **Firewall → Rules → LAN2** di pfSense kalau ragu)
- Kredensial domain admin (`Administrator` / lihat `winad-passwords.txt`)

---

## Step 1 — Verifikasi Firewall Rule Sudah Cover Ubuntu Host

Karena rule-nya source `LAN2 net`, cukup dicek aktif — gak perlu ditambah:

1. Login Web GUI pfSense (`https://10.10.10.1`)
2. **Firewall → Rules → LAN2** → pastikan rule `Allow LAN2 to WIN AD (domain join & auth)` masih ada dan posisinya di atas rule `Block LAN2 to LAN1`

---

## Step 2 — Ganti DNS di Ubuntu Host ke WIN AD

1. **Settings → Network** → klik gear di sebelah koneksi wired aktif
2. Tab **IPv4** → ganti field **DNS** (matikan toggle **Automatic** kalau perlu):

```
DNS : 10.10.10.20
```

3. **Apply** → toggle wired connection off/on biar reload

Atau lewat terminal:

```bash
sudo nmcli con mod "Wired connection 1" ipv4.dns "10.10.10.20"
sudo nmcli con up "Wired connection 1"
```

> **Catatan:** Sama seperti Win7/WinXP, WIN AD udah punya DNS Forwarder ke `8.8.8.8`/`1.1.1.1` (lihat `winad-promotion.md` Step 5) — jadi resolusi internet tetap jalan lewat satu path (WIN AD), gak perlu DNS sekunder.

---

## Step 3 — Verifikasi Konektivitas & Waktu

Kerberos (yang dipakai AD auth) sensitif ke selisih waktu — pastikan clock Ubuntu Host sinkron dulu sebelum join:

```bash
ping -c 4 10.10.10.20
nslookup lab.local
timedatectl                 # pastikan NTP synchronized: yes
```

Kalau `nslookup lab.local` gagal resolve ke `10.10.10.20`, cek ulang Step 1 (firewall) dan Step 2 (DNS). Kalau NTP belum sync:

```bash
sudo timedatectl set-ntp true
```

---

## Step 4 — Install Paket realmd/sssd

```bash
sudo apt update
sudo apt install -y realmd sssd sssd-tools libnss-sss libpam-sss adcli \
  samba-common-bin oddjob oddjob-mkhomedir packagekit
```

---

## Step 5 — Pastikan DNS Search/Routing Domain Sudah Di-set

`realm discover` butuh `_ldap`/`_kerberos` SRV record **dan** apex record `lab.local` bisa di-resolve lewat resolver default Ubuntu (bukan cuma pas di-query manual ke `10.10.10.20`). Kalau `systemd-resolved` belum tau link mana yang "punya" domain `lab.local`, query bisa gagal (`REFUSED` / `no appropriate name servers or networks for name found`) walaupun DNS server-nya udah bener.

Cek dulu:

```bash
resolvectl status
```

Lihat section link koneksi aktif (misal `Link 2 (ens33)`) — kalau **`DNS Domain:`** kosong/gak ada, tambahin dulu **sebelum lanjut ke Step 6**:

```bash
nmcli con show                              # cek nama connection persis (misal netplan-ens33)
sudo nmcli con mod "<nama-connection>" ipv4.dns-search "lab.local"
sudo nmcli con up "<nama-connection>"
```

Verifikasi sampai ini bener-bener beres sebelum lanjut:

```bash
resolvectl status         # harus muncul "DNS Domain: lab.local" di link aktif
resolvectl query lab.local
nslookup lab.local
```

> **Catatan:** Nama connection NetworkManager bisa beda-beda tergantung backend netplan yang dipakai (`Wired connection 1`, `netplan-ens33`, dll) — selalu cek dulu pakai `nmcli con show`, jangan asumsi nama default.

---

## Step 6 — Discover Domain

```bash
sudo realm discover lab.local
```

Output harus menunjukkan `lab.local`, tipe `kerberos-member`, server-software `active-directory`. Kalau muncul `No such realm found` padahal DNS Domain udah bener, jalankan `sudo realm -v discover lab.local` buat lihat detail di step mana dia stuck, terus ulangi Step 2, 3, dan 5.

---

## Step 7 — Join Domain

```bash
sudo realm join --user=Administrator lab.local
```

Masukkan password `Administrator` (lihat `winad-passwords.txt`) saat diminta. Kalau berhasil, command selesai tanpa error (realmd gak verbose kalau sukses).

---

## Step 8 — Aktifkan Auto-Create Home Directory

Biar user domain yang login pertama kali otomatis dapat home directory (`/home/LAB/username`):

```bash
sudo pam-auth-update --enable mkhomedir
```

---

## Step 9 — Login dengan Domain Account

1. Restart, atau langsung logout dari session lokal
2. Di **GDM login screen**, klik **Not listed?**
3. Masukkan username format: `p.analyst@lab.local` (format UPN, bukan `LAB\p.analyst` seperti Windows)
4. Masukkan password sesuai `winad-passwords.txt`

---

## Verifikasi

### Dari Ubuntu Host (terminal, sebelum/tanpa login domain):

```bash
realm list
# harus muncul blok lab.local dengan domain-name, realm-name, configured: kerberos-member

id Administrator@lab.local
# harus resolve UID/GID dari AD, bukan "no such user"
```

### Dari Ubuntu Host (setelah login domain):

```bash
whoami
# harus muncul: p.analyst@lab.local (atau user domain yang dipakai login)

groups
# cek group membership dari AD ikut ke-resolve
```

### Dari WIN AD (PowerShell):

```powershell
Get-ADComputer -Filter * | Select Name, DistinguishedName
```

Harus muncul `UBUNTU-VICTIM` di list — defaultnya masuk container **Computers** (bukan OU `Lab-Computers`), sama seperti Win7/WinXP.

### (Opsional) Pindahkan computer object ke OU `Lab-Computers`:

```powershell
Get-ADComputer -Identity "UBUNTU-VICTIM" | Move-ADObject -TargetPath "OU=Lab-Computers,DC=lab,DC=local"
```

---

## Troubleshooting

| Masalah | Kemungkinan Penyebab | Solusi |
|---------|----------------------|--------|
| `nslookup lab.local` / `dig lab.local @10.10.10.20` return `NOERROR` tapi `ANSWER: 0` (kosong) | Zona `lab.local` di WIN AD belum punya record apex `(same as parent folder)` type A | Di WIN AD: `ipconfig /registerdns` + `Restart-Service netlogon`, cek **DNS Manager → lab.local** ada record kosong/`(same as parent folder)` type A → `10.10.10.20`. Kalau belum muncul, tambah manual (**New Host**, Name dikosongkan, IP `10.10.10.20`) |
| `nslookup lab.local` `REFUSED`, tapi `dig lab.local @10.10.10.20` sukses (`NOERROR`) | Resolver default Ubuntu (`systemd-resolved`) gak tau link mana yang "punya" domain `lab.local` — `DNS Domain:` kosong di `resolvectl status` | Set search/routing domain: lihat **Step 5** (`nmcli con mod "<nama-connection>" ipv4.dns-search "lab.local"`) |
| `realm -v discover lab.local` stuck di `Resolving: lab.local` → `No results: lab.local` walau SRV record udah ketemu | Sama seperti di atas (DNS Domain routing belum di-set), atau cache negatif lama di `systemd-resolved` | Beresin Step 5 dulu, lalu `sudo resolvectl flush-caches` (atau `sudo systemctl restart systemd-resolved`) |
| `realm discover lab.local` gak return apa-apa | DNS belum diarahkan ke `10.10.10.20`, atau firewall rule belum aktif | Ulangi Step 1 & Step 2, cek `nslookup lab.local` |
| `realm join` gagal dengan error Kerberos (`clock skew too great`) | Waktu Ubuntu Host beda jauh dari WIN AD | Cek `timedatectl`, pastikan NTP synchronized, `sudo timedatectl set-ntp true` |
| `realm join` gagal, password ditolak | Salah password, atau username salah format | Coba `--user=Administrator` (bukan `LAB\Administrator` — beda dari Windows), cocokkan password di `winad-passwords.txt` |
| Login domain user gak muncul opsi di GDM | `libpam-sss`/`libnss-sss` belum terinstall, atau perlu restart | Cek Step 4, restart VM setelah join |
| Login domain user berhasil tapi gak dapat home directory | `pam-auth-update --enable mkhomedir` belum dijalankan | Ulangi Step 8, logout/login lagi |
| `id Administrator@lab.local` return "no such user" | sssd belum reload cache, atau join gagal silent | `sudo systemctl restart sssd`, cek `realm list` masih `configured: kerberos-member` |

---

## Catatan Keamanan Lab

Sama seperti Win7/WinXP, firewall rule `Allow LAN2 to WIN AD` ini **permanen aktif** karena domain-joined machine perlu terus-menerus komunikasi ke DC (Kerberos ticket renewal, SSSD cache refresh). Default `realm join` gak otomatis batasi user AD mana yang boleh login lokal (semua domain user bisa login) — untuk lab ini dibiarkan default (open), tapi di environment production biasanya dibatasi pakai `access_provider = simple` + `simple_allow_groups` di `/etc/sssd/sssd.conf`.
