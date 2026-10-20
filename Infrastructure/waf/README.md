# 🧱 WAF Lab — Overview (1 VM, Multi-Stack)

## Tujuan

Bangun **WAF sebagai reverse proxy di depan DVWA**, dengan beberapa stack WAF di **satu VM** (`10.10.10.5`), buat dipelajari dan diadu kemampuan **block + detect** serangan web. WAF berperan sebagai **active response** sekaligus **sumber telemetri deteksi** di Wazuh.

| Stack | Folder | Karakter | Status |
|-------|--------|----------|--------|
| **ModSecurity + OWASP CRS** (image resmi) | [`modsecurity-crs/`](./modsecurity-crs/README.md) | Image `owasp/modsecurity-crs:nginx`, siap pakai, engine regex/signature + anomaly scoring | ✅ LIVE end-to-end |
| **ModSecurity from scratch** | [`modsecurity-scratch/`](./modsecurity-scratch/README.md) | Nginx + libmodsecurity v3 + connector + rules dirakit dan di-compile sendiri, buat paham tiap komponen | 🚧 Dikerjain |
| **SafeLine** | `safeline/` | WAF managed dengan dashboard, engine **semantic analysis** | 📝 Blueprint |

Angle lab ini **blue team / detection + response**. Web-Server udah matang di sisi **detection** (network via Suricata/pfSense + endpoint via agent/auditd/FIM/CSP), jadi WAF ini step pertama masuk ranah **response**. Yang dinilai dua hal:

1. **Response**: seberapa efektif tiap WAF **block** serangan, dan gimana perilaku block-nya.
2. **Detection**: apa yang tiap WAF **detect vs lewatkan**, dan gimana **log-nya masuk Wazuh** jadi alert buat analis.

Ini bagian dari progres response bertahap: **WAF → network (Suricata IPS) → firewall (pfSense block / active-response)**. Writeup lab-nya ada di [`../../Labs/waf/`](../../Labs/waf/).

---

## 🗺️ Arsitektur & Alur

Attacker (Kali) gak lagi mukul DVWA langsung. Dia mukul WAF, dan WAF yang nerusin ke backend DVWA.

```
[Kali @ 192.168.43.x]                      ← external attacker (hotspot)
        |
   [pfSense WAN:80] ── NAT port-forward ──► 10.10.10.5:80   (WAF VM)
        |
   [WAF VM @ 10.10.10.5]  ── reverse proxy ──► http://10.10.10.10:80   (DVWA, Apache, LAN1)
        |
   (log WAF) ──► Wazuh Agent `waf` ──► Manager @ Dell
```

### Alokasi port di WAF VM

| Stack | Port host | Diakses dari |
|-------|-----------|--------------|
| ModSecurity + CRS | `:80` | NAT pfSense (Kali / attacker external) |
| ModSecurity scratch | `:80` | NAT pfSense |
| SafeLine | `:80` + dashboard `:9443` | NAT pfSense |

Semua stack pakai `:80`, jadi cuma **satu yang nyala dalam satu waktu** (lihat bagian Toggle). Target NAT pfSense tetap `10.10.10.5:80`, jadi ganti stack gak perlu ubah NAT.

**Baseline tanpa WAF:** arahin ulang NAT pfSense ke `10.10.10.10` (direct DVWA) buat bandingin serangan tanpa WAF.

---

## 📋 Prerequisites

- VM **Ubuntu Server 24.04** (ISO yang sama dengan Web-Server), flow install base ikutin [`../web-server-setup.md`](../web-server-setup.md)
  - Hostname `waf`, user `anang`
  - VMware: 1 processor × 2 core, RAM **6 GB** (SafeLine rakus: postgres + detector + mgt)
  - NIC → **VMnet2 (LAN1)**, static IP `10.10.10.5/24` via netplan, gateway `10.10.10.1`
- DVWA di `10.10.10.10:80` udah jalan, lihat [`../dvwa-setup.md`](../dvwa-setup.md)
- pfSense running dan port-forward DVWA udah pernah dibuat, lihat [`../dvwa-external-access.md`](../dvwa-external-access.md)
- Wazuh Manager di Dell running, lihat [`../wazuh-setup.md`](../wazuh-setup.md)
- Kredensial VM / dashboard disimpan di `waf-passwords.txt` (gitignored, `*-passwords.txt`). **Jangan commit.**

---

## 🐳 Step 1: Install Docker (base VM)

Semua stack WAF jalan di Docker.

```bash
sudo apt update && sudo apt install -y ca-certificates curl gnupg

sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

sudo usermod -aG docker anang    # re-login setelah ini

docker --version && docker compose version
```

Struktur folder kerja di VM (runtime di host, bukan di repo):

```
/data/waf/
├── modsec-crs/     ← stack ModSecurity + CRS (image resmi)
└── scratch/        ← stack ModSecurity from scratch
/data/safeline/     ← stack SafeLine
```

---

## 🔀 Step 2: Toggle Stack di `:80`

Semua stack listen `:80`, jadi cuma satu yang nyala per waktu. Pola: **`down` stack yang lagi nyala, baru `up` stack yang mau dites.**

```bash
cd /data/waf/modsec-crs  && docker compose down     # atau stack lain yang lagi nyala
cd /data/waf/scratch     && docker compose up -d    # stack yang mau dites
```

| Stack | Folder compose |
|-------|----------------|
| ModSecurity + CRS | `/data/waf/modsec-crs` |
| ModSecurity scratch | `/data/waf/scratch` |
| SafeLine | `/data/safeline` |

**Cek siapa yang pegang port:**
```bash
sudo ss -ltnp 'sport = :80'
docker ps --format '{{.Names}}\t{{.Ports}}'
```

---

## 🌐 Step 3: Repoint NAT pfSense ke WAF

Di [`../dvwa-external-access.md`](../dvwa-external-access.md), port-forward `WAN:80` ngarah ke DVWA `10.10.10.10` langsung. Buat lab WAF, arahin ke WAF VM:

1. pfSense → **Firewall → NAT → Port Forward** → edit rule DVWA
2. **Redirect target IP**: `10.10.10.10` → **`10.10.10.5`**. Port tetap `80`.
3. **Save → Apply Changes**

NAT port-forward cuma ngubah **tujuan**, source IP attacker gak berubah. Jadi WAF tetap lihat IP attacker asli.

**Baseline:** balikin **Redirect target IP** ke `10.10.10.10`.

---

## 📡 Step 4: Wazuh Agent

Satu agent di WAF VM buat semua stack. Ikutin pola [`../web-server-wazuh-agent.md`](../web-server-wazuh-agent.md), **agent name `waf`**:

```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
sudo chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt update
sudo WAZUH_MANAGER='<IP-DELL>' WAZUH_AGENT_NAME='waf' apt install -y wazuh-agent
sudo systemctl daemon-reload && sudo systemctl enable --now wazuh-agent
```

Konfigurasi `<localfile>` buat log tiap stack ada di README stack masing-masing.

---

## ✅ Verifikasi

- Agent `waf` **Active** di Wazuh Dashboard
- `docker ps` nunjukin container stack yang lagi dites
- `sudo ss -ltnp` cuma satu proses di `:80`
- Dari luar: `curl -I http://<IP-WAN-pfSense>/` dapat response DVWA lewat WAF

Verifikasi serangan + log per stack ada di README masing-masing.

---

## 🧷 Catatan & Gotcha

- **Satu `:80` doang**: selalu `down` stack lama sebelum `up` yang baru, kalau gak compose error bind port.
- **Backend IP** taruh di `.env`, jangan hardcode di compose (IP LAN1 bisa berubah).
- **IP attacker asli** ada di log WAF. Access log Apache di Web-Server nyatat IP WAF (`10.10.10.5`), kecuali Apache dipasang `mod_remoteip` yang baca header `X-Real-IP` dari WAF.
- **Perbandingan fair**: stack di `:80` jalan gantian, jadi adu dengan **payload Kali yang sama** ke tiap WAF, catat hasilnya di writeup `Labs/waf/`.
- **Browser timeout padahal WAF jalan**: browser (Firefox HTTPS-First) nyoba `https://` dulu, padahal yang di-forward cuma `:80`. Ketik URL lengkap `http://<IP-WAN-pfSense>/`. Cek cepat: `curl -sI http://<IP-WAN-pfSense>/login.php` dari terminal.
- **Akses dari M1**: HTTP lewat NAT pfSense (`http://<IP-WAN-pfSense>/`), SSH `10.10.10.5:22` lewat WireGuard (lihat [`../pfsense-wireguard-setup.md`](../pfsense-wireguard-setup.md)).
