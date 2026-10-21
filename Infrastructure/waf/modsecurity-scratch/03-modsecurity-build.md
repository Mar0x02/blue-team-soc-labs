# 🔧 Tahap 3 — Build ModSecurity (libmodsecurity + Connector)

> 🚧 **Belum dijalanin.** Dockerfile, compose, dan conf di bawah masih rancangan. Hasil yang diharapkan di Verifikasi ditandai `🔬 VALIDATE`. Bagian dari [ModSecurity build from scratch](./README.md), nyakup roadmap Tahap 3–4.

## Tujuan

Rakit image nginx yang bisa jalanin ModSecurity, **dari source**, tanpa image siap pakai:

1. **Compile libmodsecurity v3** (engine-nya) dan lihat dependency apa aja yang dibutuhin
2. **Compile connector** `ModSecurity-nginx` jadi dynamic module (`.so`), dari source nginx yang **versinya sama persis** dengan image
3. **Load module** di nginx dan buktiin engine-nya hidup pakai **satu rule smoke test**

Belum ada rule beneran, belum ada `modsecurity.conf`. Itu urusan `04-modsecurity-basic-rules.md` (Tahap 5–6). Tahap ini cuma mastiin **mesinnya bisa nyala**.

| Komponen | Versi | Sumber |
|----------|-------|--------|
| nginx | `1.28.0` | Image resmi `nginx:1.28.0` (Debian bookworm) + source `nginx-1.28.0.tar.gz` |
| libmodsecurity | `v3.0.17` (rilis 2026-09-29) | [owasp-modsecurity/ModSecurity](https://github.com/owasp-modsecurity/ModSecurity) |
| Connector | `v1.0.4` (rilis 2025-05-21) | [owasp-modsecurity/ModSecurity-nginx](https://github.com/owasp-modsecurity/ModSecurity-nginx) |

---

## Prerequisites

- Tahap 2 selesai, lihat [`02-nginx-native-filter.md`](./02-nginx-native-filter.md)
- WAF VM bisa akses internet (clone GitHub + download nginx.org) lewat pfSense
- Disk kosong ±3 GB buat build cache. Compile di VM 2 core makan waktu kira-kira 10–20 menit

---

## Step-by-Step

**Struktur di VM:**

```
/data/waf/scratch/
├── .env
├── Dockerfile                          ← baru
├── docker-compose.yml                  ← base: nginx polos (Tahap 1–2), gak diubah
├── docker-compose.override.yml         ← baru: build + modsec (Tahap 3)
├── conf/
│   └── nginx/
│       ├── tahap-1-reverse-proxy.conf
│       ├── tahap-2-native-filter.conf
│       ├── tahap-3-modsecurity.conf    ← baru
│       └── modsec/
│           └── main.conf               ← baru: directive + rule ModSecurity
└── logs/
```

Nomor conf ngikutin nomor file doc: `tahap-3-*.conf` dipakai di doc `03-`, `tahap-4-*.conf` nanti di doc `04-`.

### 1. Dockerfile (multi-stage)

```dockerfile
ARG NGINX_VERSION=1.28.0

FROM nginx:${NGINX_VERSION} AS builder

ARG NGINX_VERSION
ARG MODSEC_VERSION=v3.0.17
ARG CONNECTOR_VERSION=v1.0.4

RUN apt-get update && apt-get install -y --no-install-recommends \
        git ca-certificates wget build-essential autoconf automake libtool pkgconf \
        libpcre2-dev libxml2-dev libyajl-dev libcurl4-openssl-dev liblmdb-dev \
        zlib1g-dev libssl-dev

WORKDIR /src

RUN git clone --depth 1 -b ${MODSEC_VERSION} --recursive \
        https://github.com/owasp-modsecurity/ModSecurity.git \
    && cd ModSecurity \
    && ./build.sh \
    && ./configure --with-pcre2 --disable-doxygen-doc --disable-examples \
    && make -j"$(nproc)" \
    && make install

RUN git clone --depth 1 -b ${CONNECTOR_VERSION} \
        https://github.com/owasp-modsecurity/ModSecurity-nginx.git \
    && wget -q https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz \
    && tar xzf nginx-${NGINX_VERSION}.tar.gz \
    && cd nginx-${NGINX_VERSION} \
    && ./configure --with-compat --add-dynamic-module=/src/ModSecurity-nginx \
    && make modules

FROM nginx:${NGINX_VERSION}

ARG NGINX_VERSION

RUN apt-get update && apt-get install -y --no-install-recommends \
        libxml2 libyajl2 libcurl4 liblmdb0 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/modsecurity/lib/ /usr/local/modsecurity/lib/
COPY --from=builder /src/nginx-${NGINX_VERSION}/objs/ngx_http_modsecurity_module.so /usr/lib/nginx/modules/
COPY --from=builder /src/ModSecurity/unicode.mapping /etc/nginx/modsec/unicode.mapping
COPY --from=builder /src/ModSecurity/modsecurity.conf-recommended /etc/nginx/modsec/modsecurity.conf-recommended
```

| Bagian | Fungsi |
|--------|--------|
| `FROM nginx:${NGINX_VERSION} AS builder` | Stage builder pakai **image yang sama** dengan stage final, jadi OS, compiler, dan library-nya cocok |
| `libpcre2-dev`, `libxml2-dev`, `libyajl-dev`, `libcurl4-openssl-dev`, `liblmdb-dev` | Dependency libmodsecurity: regex (`@rx`), parsing body XML, parsing body JSON, `SecRemoteRules`, dan penyimpanan collection persisten |
| `--recursive` | ModSecurity punya **submodule** (`libinjection` buat `@detectSQLi`/`@detectXSS`, `mbedtls`). Tanpa ini build gagal |
| `./build.sh` → `./configure` → `make install` | Pola autotools. Hasilnya di `/usr/local/modsecurity/` (`lib/libmodsecurity.so.3`, header di `include/`) |
| `--disable-doxygen-doc --disable-examples` | Lewatin bikin dokumentasi dan contoh, biar build lebih cepat |
| `./configure --with-compat` | Bikin module yang **kompatibel binary** sama nginx dari package resmi (yang juga di-build `--with-compat`). Tanpa ini nginx nolak load module |
| `--add-dynamic-module` + `make modules` | Cuma compile module-nya, gak compile ulang nginx |
| Stage final | Cuma runtime library (tanpa `-dev`, tanpa compiler) + `libmodsecurity` + `.so`. Image jauh lebih kecil dari stage builder |
| `/usr/local/modsecurity/lib/` path sama | Connector di-link pakai **rpath** ke path ini. Kalau path di stage final beda, module gagal load (`libmodsecurity.so.3: cannot open shared object file`) |
| `unicode.mapping`, `modsecurity.conf-recommended` | Belum dipakai di tahap ini, disiapin buat Tahap 5 (`SecUnicodeMapFile`, config engine) |

### 2. `docker-compose.yml` + `docker-compose.override.yml`

Compose dipecah dua pakai **override pattern**. Base (`docker-compose.yml`) **gak berubah** dari Tahap 1–2 — tetap `image: nginx:1.28.0` polos. Yang khusus Tahap 3 (build image + mount rule ModSecurity) ditaruh di `docker-compose.override.yml`, dan `docker compose` **otomatis nge-merge** override itu ke base tiap `up`/`build` tanpa flag.

**`docker-compose.yml` (base — sama kayak Tahap 1–2, gak diubah):**

```yaml
services:
  waf-scratch:
    image: nginx:1.28.0
    container_name: waf-scratch
    restart: unless-stopped
    env_file: .env
    environment:
      - NGINX_ENVSUBST_OUTPUT_DIR=/etc/nginx
    ports:
      - "80:8080"
    volumes:
      - ./conf/nginx/${NGINX_CONF}:/etc/nginx/templates/nginx.conf.template:ro
      - ./logs:/var/log/nginx
```

**`docker-compose.override.yml` (cuma yang beda di Tahap 3):**

```yaml
services:
  waf-scratch:
    build:
      context: .
      args:
        NGINX_VERSION: "1.28.0"
        MODSEC_VERSION: "v3.0.17"
        CONNECTOR_VERSION: "v1.0.4"
    image: waf-scratch:nginx-1.28.0-modsec-3.0.17
    volumes:
      - ./conf/nginx/modsec/main.conf:/etc/nginx/modsec/main.conf:ro
```

Override cuma nulis yang **beda** dari base — `container_name`, `ports`, `env_file`, `environment`, dan volume template + logs diwarisin dari base pas di-merge, jadi gak perlu diulang. Volume di-merge **by target path**, jadi mount `main.conf` ini **nambah** ke dua volume base, bukan ganti.

| Baris override | Fungsi |
|----------------|--------|
| `build:` + `args` | Image dirakit dari `Dockerfile` di folder ini; versi dikunci di sini (`NGINX_VERSION` harus sama dengan source nginx yang di-compile) |
| `image: waf-scratch:...` | Nimpa `image: nginx:1.28.0` dari base, sekaligus jadi tag hasil build (keliatan di `docker images`) |
| mount `main.conf` | File rule ModSecurity, dibaca lewat `include` di conf nginx (Step 3) |

**Gotcha penting:** `docker-compose.override.yml` **auto-kebaca** tiap `docker compose up` tanpa flag apa pun — jadi default sekarang = **Tahap 3**. Buat jalanin Tahap 1–2 (nginx polos, tanpa build modsec), override harus di-skip eksplisit:

| Mau jalanin | Command |
|-------------|---------|
| Tahap 3 (build + modsec) | `docker compose up -d` |
| Tahap 1–2 (nginx polos) | `docker compose -f docker-compose.yml up -d` |

### 3. `conf/nginx/tahap-3-modsecurity.conf` + `conf/nginx/modsec/main.conf`

Basisnya **Tahap 1** (reverse proxy polos), bukan Tahap 2, biar yang nge-block cuma ModSecurity dan gak ketuker sama rule native nginx. Directive ModSecurity dipisah ke file sendiri (`modsec/main.conf`) yang di-`include` — jadi mulai Tahap 5 tinggal ganti isi `main.conf` tanpa nyentuh conf nginx utama.

**`conf/nginx/tahap-3-modsecurity.conf`:**

```nginx
load_module modules/ngx_http_modsecurity_module.so;

events {
    worker_connections 1024;
}

http {
    server_tokens off;
    proxy_http_version 1.1;

    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log warn;

    server {
        listen 8080;
        server_name _;

        include /etc/nginx/modsec/main.conf;

        location / {
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;

            proxy_pass ${BACKEND_URL};
        }
    }
}
```

**`conf/nginx/modsec/main.conf`:**

```nginx
modsecurity on;
modsecurity_rules '
    SecRuleEngine On
    SecRule ARGS:test "@streq attack" "id:100001,phase:1,deny,status:403,log,msg:tahap3-smoke-test"
';
```

| Directive | Fungsi |
|-----------|--------|
| `load_module` | Wajib di **main context** (paling atas, di luar `http`). Ini alasan dari Tahap 1 kita pakai conf nginx utuh |
| `include /etc/nginx/modsec/main.conf` | Tarik directive ModSecurity dari file terpisah. File-nya di-mount read-only lewat override (Step 2), **bukan** lewat template envsubst, jadi gak kena substitusi variabel |
| `modsecurity on` | Nyalain connector buat server ini. Request diteruskan ke libmodsecurity sebelum di-`proxy_pass` |
| `modsecurity_rules '...'` | Rule **inline** di `main.conf`, cukup buat smoke test. Mulai Tahap 5 diganti `modsecurity_rules_file` yang nunjuk ke `modsecurity.conf` + file rule |
| `SecRuleEngine On` | Engine mode blocking. Default-nya `Off` kalau gak diset |
| `SecRule ARGS:test "@streq attack" ...` | Kalau parameter `test` isinya persis `attack` → `deny` dengan `403` di phase 1 (request headers, query string udah kebaca) |
| `id:100001` | Range custom rule `100000–199999`, sama kayak konvensi di stack CRS |

Kenapa di-`include`, bukan ditempel langsung di conf nginx? Mulai Tahap 5 isi `main.conf` tumbuh (config engine + banyak SecRule). Misahin dari awal bikin conf nginx utama stabil, yang berubah cukup `main.conf`.

Rule smoke test ditulis tanpa tanda kutip di `msg` biar gak bentrok sama kutip tunggal pembungkus `modsecurity_rules`. Gak ada `$` di rule, jadi aman walau kalau nanti dilewatin envsubst.

### 4. Build & jalanin

```bash
# dari Mac
cd Infrastructure/waf/modsecurity-scratch
scp -r Dockerfile docker-compose.yml docker-compose.override.yml conf anang@10.10.10.5:/data/waf/scratch/

# di VM
cd /data/waf/scratch
sed -i 's/^NGINX_CONF=.*/NGINX_CONF=tahap-3-modsecurity.conf/' .env
docker compose build                       # lama, compile libmodsecurity + connector (override auto-kebaca)
docker compose up -d --force-recreate
docker exec waf-scratch nginx -t
```

Semua command di atas **tanpa `-f`**, jadi override auto-kebaca dan yang jalan Tahap 3. Buat balik ke Tahap 1–2 nanti: ganti `NGINX_CONF` ke conf tahap itu, terus `docker compose -f docker-compose.yml up -d --force-recreate` (override di-skip, pakai image `nginx:1.28.0` polos tanpa build ulang).

Kalau build gagal, scroll ke error **pertama** di output `docker compose build`, bukan yang terakhir. Biasanya dependency `-dev` yang kurang (`configure: error: ... not found`).

---

## Verifikasi

> 🔬 **VALIDATE** — semua hasil masih harapan, diisi hasil asli pas dijalanin.

### 1. Artefak build

```bash
docker images waf-scratch                                                        # tag nginx-1.28.0-modsec-3.0.17 ada
docker exec waf-scratch nginx -v                                                 # nginx version: nginx/1.28.0
docker exec waf-scratch ls -l /usr/lib/nginx/modules/ngx_http_modsecurity_module.so
docker exec waf-scratch ls -l /usr/local/modsecurity/lib/
docker exec waf-scratch sh -c 'ldd /usr/local/modsecurity/lib/libmodsecurity.so.3 | grep "not found"'   # harus kosong
docker exec waf-scratch sh -c 'ldd /usr/lib/nginx/modules/ngx_http_modsecurity_module.so | grep modsecurity'
```

| Cek | Harapan |
|-----|---------|
| `ldd ... grep "not found"` | Kosong. Kalau ada baris, berarti runtime library di stage final kurang, tambahin package-nya di `apt-get install` stage final |
| `ldd` module | `libmodsecurity.so.3 => /usr/local/modsecurity/lib/libmodsecurity.so.3` |

### 2. Engine hidup

```bash
docker logs waf-scratch 2>&1 | tail -20
cat /data/waf/scratch/logs/error.log
```

Harapan: ada baris `ModSecurity-nginx v1.0.4 (rules loaded inline/local/remote: 1/0/0)` di `error.log` waktu nginx start. Angka `1` = rule smoke test kebaca.

### 3. Smoke test

Dari Mac:

```bash
WAF=http://192.168.43.100
curl -s -o /dev/null -w "normal       %{http_code}\n" "$WAF/login.php"
curl -s -o /dev/null -w "test=aman    %{http_code}\n" "$WAF/login.php?test=aman"
curl -s -o /dev/null -w "test=attack  %{http_code}\n" "$WAF/login.php?test=attack"
```

| Uji | Harapan |
|-----|---------|
| normal | `200` |
| `test=aman` | `200`, nilai beda, rule gak match |
| `test=attack` | `403`, diblok ModSecurity |

Di VM:

```bash
grep ModSecurity /data/waf/scratch/logs/error.log | tail -3
```

Harapan: `ModSecurity: Access denied with code 403 (phase 1). Matched "Operator `StrEq' with parameter `attack' against variable `ARGS:test' ..." [id "100001"] [msg "tahap3-smoke-test"]`.

### 4. Pembanding sama Tahap 2

Payload yang lolos di Tahap 2 (`%3Cscript%3E`, `' OR '1'='1`) **masih lolos** di tahap ini, karena belum ada rule selain smoke test. Itu wajar: tahap ini cuma buktiin mesinnya nyala. Payload yang sama ditembak lagi di Tahap 5–6 setelah ada rule + transformation.
