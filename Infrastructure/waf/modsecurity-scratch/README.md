# 🔧 WAF Stack — ModSecurity Build from Scratch

> 🚧 **STATUS: DIKERJAIN.** Tahap yang udah selesai ditandai ✅ di Roadmap.

## Tujuan

Rakit WAF ModSecurity **dari nol**: compile engine, connector, dan pasang rules sendiri, tanpa image siap pakai. Tujuannya paham **tiap komponen** yang di image `owasp/modsecurity-crs:nginx` (stack [`../modsecurity-crs/`](../modsecurity-crs/README.md)) udah dibungkus jadi satu:

```
① NGINX               ② ENGINE                      ③ RULES
 reverse proxy  ──►    libmodsecurity v3      ──►    SecRule custom → OWASP CRS
 (proxy_pass)          (parsing, phase,              (anomaly scoring,
                        transformation, audit log)    paranoia level)
        └── connector: ngx_http_modsecurity_module (.so) ──┘
```

Stack ini jalan di **`:80`**, sama kayak stack lain, jadi **gantian** sama ModSecurity + CRS (toggle `down`/`up`, lihat [`../README.md`](../README.md)). NAT pfSense tetap ke `10.10.10.5:80`, jadi bisa langsung diserang dari luar kayak stack CRS.

---

## Prerequisites

- WAF VM + Docker siap, lihat [`../README.md`](../README.md)
- Folder kerja di VM: `/data/waf/scratch`
- DVWA di `10.10.10.10:80` jalan
- Stack lain yang pegang `:80` di-`down` dulu:
  ```bash
  cd /data/waf/modsec-crs && docker compose down
  ```

---

## Roadmap

Tiap tahap punya file sendiri dengan format Tujuan → Prerequisites → Step-by-Step → Verifikasi.

| Tahap | File | Yang dibangun | Yang dipelajari | Status |
|-------|------|---------------|-----------------|--------|
| 1 | [`01-nginx-reverse-proxy.md`](./01-nginx-reverse-proxy.md) | **Nginx polos** sebagai reverse proxy ke DVWA (tanpa WAF) | `proxy_pass`, header `X-Real-IP` / `X-Forwarded-For`, template envsubst | ✅ |
| 2 | [`02-nginx-native-filter.md`](./02-nginx-native-filter.md) | **Rule native nginx** (tanpa ModSecurity) + log ke file | `map`, `if`/`return`, `location`, `limit_req`, `log_format`, dan **batasan** WAF berbasis regex mentah | ✅ |
| 3 | [`03-modsecurity-build.md`](./03-modsecurity-build.md) | **Compile libmodsecurity v3** + **connector** `ModSecurity-nginx` (`.so`, versi nginx harus sama persis) | Dependency engine (PCRE2, libxml2, yajl, curl, dll), `load_module` | ✅ |
| 4 | [`04-modsecurity-basic-rules.md`](./04-modsecurity-basic-rules.md) | **SecRule tulisan sendiri** tanpa CRS + **anomaly scoring** + **paranoia gating** (PL1 block vs PL2 shadow) | variable / operator (`@detectSQLi`,`@detectXSS`,`@rx`) / transformation / action, `pass`/`block`/`deny`, `skipAfter`/`SecMarker`, ember skor per-PL | 🚧 |
| 5 | `05-modsecurity-owasp-crs.md` | **Pasang OWASP CRS manual** _(opsional)_ | `crs-setup.conf`, urutan include, anomaly scoring, paranoia | ⏸️ Diputusin nanti |
| 6 | `06-wazuh-integration.md` | **Log → Wazuh** | `<localfile>` + ingest ke agent `waf` | ⏳ |

File yang belum ada linknya dibikin pas tahapnya mulai dikerjain.

Tahap 5 **opsional**. Stack ini bisa tetap pakai SecRule tulisan sendiri tanpa CRS, karena perbandingan dengan CRS udah ada di stack [`../modsecurity-crs/`](../modsecurity-crs/README.md). Tahap 6 (Wazuh) tetap jalan dengan atau tanpa Tahap 5.

Dockerfile pakai **multi-stage build**: stage builder buat compile, stage final cuma berisi nginx + module + library runtime. Versi tiap komponen (nginx, ModSecurity, connector, CRS) dikunci dan dicatat di sini.

File build (Dockerfile, compose, config) disimpan di folder ini dan di-sync ke `/data/waf/scratch` di VM.

---

## Struktur Folder

```
modsecurity-scratch/
├── README.md                     ← file ini
├── 01-nginx-reverse-proxy.md
├── 02-nginx-native-filter.md
├── 03-modsecurity-build.md
├── 04-modsecurity-basic-rules.md
├── Dockerfile                    ← mulai Tahap 3
├── docker-compose.yml            ← base: nginx polos (Tahap 1–2)
├── docker-compose.override.yml   ← mulai Tahap 3: build + modsec
└── conf/
    └── nginx/
        ├── tahap-1-reverse-proxy.conf
        ├── tahap-2-native-filter.conf
        ├── tahap-3-modsecurity.conf
        └── modsec/
            ├── main.conf         ← engine + init + keputusan (Tahap 3+)
            └── rules/            ← SecRule custom (Tahap 4)
                ├── rules-command-injection.conf ← direct deny (shell syntax)
                ├── rules-path-traversal.conf ← direct deny (traversal/LFI)
                ├── rules-sqli.conf   ← PL1 @detectSQLi (block)
                ├── rules-xss.conf    ← PL1 @detectXSS (block)
                └── tune-rules.conf   ← PL2 shadow + gerbang (detection)
```

Conf nginx dipisah **per tahap**, jadi tahap lama bisa dijalanin ulang kapan aja. Compose milih file lewat `NGINX_CONF` di `.env` VM (gitignored, bikin manual):

```ini
BACKEND_URL=http://10.10.10.10:80
NGINX_CONF=tahap-2-native-filter.conf
```

Compose otomatis baca `.env` di folder project buat ngisi `${NGINX_CONF}` di `docker-compose.yml`. Conf Tahap 1–2 tetap jalan di image hasil build ModSecurity nanti (versi nginx sama, tanpa `load_module`), tapi conf ModSecurity gak jalan di image `nginx:1.28.0` biasa. Screenshot ada di [`../asset/modsecurity-scratch/`](../asset/modsecurity-scratch/) dengan prefix `tahap-N-`.

---

## Cara Apply Perubahan Config

Conf dirender dari template (envsubst) **cuma waktu container dibuat**, jadi tiap perubahan isi conf **atau** ganti `NGINX_CONF` harus `--force-recreate`:

```bash
# dari Mac
cd Infrastructure/waf/modsecurity-scratch
scp -r Dockerfile docker-compose.yml docker-compose.override.yml conf anang@10.10.10.5:/data/waf/scratch/

# di VM
cd /data/waf/scratch
docker compose up -d --force-recreate        # Tahap 3 (override auto-kebaca)
docker exec waf-scratch nginx -t
docker logs waf-scratch 2>&1 | tail -20      # pastiin gak ada [emerg]
```

Mulai Tahap 3, `docker-compose.override.yml` **auto-kebaca** tiap `docker compose up` tanpa flag — defaultnya jalan Tahap 3 (build image ModSecurity + mount `main.conf`). Buat jalanin ulang Tahap 1–2 (nginx polos, tanpa build), skip override eksplisit: `docker compose -f docker-compose.yml up -d --force-recreate`.

| Command | Ngerender ulang conf? |
|---------|-------------------------------|
| `docker compose up -d` | ❌ Gak, kalau compose-nya gak berubah |
| `docker exec waf-scratch nginx -s reload` | ❌ Gak |
| `docker compose restart` | ✅ Iya (entrypoint jalan lagi) |
| `docker compose up -d --force-recreate` | ✅ Iya, **paling aman** |

Kalau container `Restarting` / `Exited`, hampir pasti config salah ketik. Pesan `[emerg]` di `docker logs` nunjukin baris yang error.

