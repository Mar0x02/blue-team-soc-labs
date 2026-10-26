# 🔧 Tahap 3 — Build ModSecurity (libmodsecurity + Connector)

> **Status:** Iterasi 1 (rule inline) ✅ **LIVE 2026-10-22** — engine kebukti nyala & nge-block. Iterasi 2 (file-based + kerangka anomaly scoring) ✅ **LIVE 2026-10-23** — SQLi ke-block via anomaly chain, audit log JSON jalan (permission uid 101 resolved). Bagian dari [ModSecurity build from scratch](./README.md), nyakup roadmap Tahap 3.

## Tujuan

Rakit image nginx yang bisa jalanin ModSecurity, **dari source**, tanpa image siap pakai:

1. **Compile libmodsecurity v3** (engine-nya) dan lihat dependency apa aja yang dibutuhin
2. **Compile connector** `ModSecurity-nginx` jadi dynamic module (`.so`), dari source nginx yang **versinya sama persis** dengan image
3. **Load module** di nginx dan buktiin engine-nya hidup

Dikerjain dalam **2 iterasi**:

- **Iterasi 1 — rule inline:** satu rule smoke test ditempel langsung lewat `modsecurity_rules '...'`. Tujuannya cuma mastiin **mesinnya nyala**. ✅ *(udah live)*
- **Iterasi 2 — file-based:** rule dipindah ke file sendiri (`modsecurity_rules_file` + `Include`), ditambah config engine, audit log JSON, dan kerangka anomaly scoring. Lebih terorganisir dan mendekati cara CRS kerja. ✅ *(live 2026-10-23)*

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
│           ├── main.conf               ← config engine + (Iterasi 2) loader rule
│           └── rules/                   ← (Iterasi 2) file rule per-kategori
│               └── rules-sqli.conf
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
| `libpcre2-dev`, `libxml2-dev`, `libyajl-dev`, `libcurl4-openssl-dev`, `liblmdb-dev` | Dependency libmodsecurity: regex (`@rx`), parsing body XML, parsing body JSON (+ audit log JSON), `SecRemoteRules`, dan penyimpanan collection persisten |
| `--recursive` | ModSecurity punya **submodule** (`libinjection` buat `@detectSQLi`/`@detectXSS`, `mbedtls`). Tanpa ini build gagal |
| `./build.sh` → `./configure` → `make install` | Pola autotools. Hasilnya di `/usr/local/modsecurity/` (`lib/libmodsecurity.so.3`, header di `include/`) |
| `--disable-doxygen-doc --disable-examples` | Lewatin bikin dokumentasi dan contoh, biar build lebih cepat |
| `./configure --with-compat` | Bikin module yang **kompatibel binary** sama nginx dari package resmi (yang juga di-build `--with-compat`). Tanpa ini nginx nolak load module |
| `--add-dynamic-module` + `make modules` | Cuma compile module-nya, gak compile ulang nginx |
| Stage final | Cuma runtime library (tanpa `-dev`, tanpa compiler) + `libmodsecurity` + `.so`. Image jauh lebih kecil dari stage builder |
| `/usr/local/modsecurity/lib/` path sama | Connector di-link pakai **rpath** ke path ini. Kalau path di stage final beda, module gagal load (`libmodsecurity.so.3: cannot open shared object file`) |
| `unicode.mapping`, `modsecurity.conf-recommended` | Belum dipakai penuh di tahap ini, disiapin buat Tahap 4 (`SecUnicodeMapFile`, config engine lengkap) |

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
      - ./conf/nginx/modsec/rules:/etc/nginx/modsec/rules:ro
```

Override cuma nulis yang **beda** dari base — `container_name`, `ports`, `env_file`, `environment`, dan volume template + logs diwarisin dari base pas di-merge, jadi gak perlu diulang. Volume di-merge **by target path**, jadi dua mount ini **nambah** ke volume base, bukan ganti.

| Baris override | Fungsi |
|----------------|--------|
| `build:` + `args` | Image dirakit dari `Dockerfile` di folder ini; versi dikunci di sini (`NGINX_VERSION` harus sama dengan source nginx yang di-compile) |
| `image: waf-scratch:...` | Nimpa `image: nginx:1.28.0` dari base, sekaligus jadi tag hasil build (keliatan di `docker images`) |
| mount `main.conf` | Config ModSecurity, dibaca conf nginx (Step 3) |
| mount `rules/` | **(ditambah di Iterasi 2)** folder file rule yang di-`Include` dari `main.conf`. **Jangan** mount `/etc/nginx/modsec/` penuh — bakal nutupin `unicode.mapping` + `modsecurity.conf-recommended` bawaan image |

**Gotcha penting:** `docker-compose.override.yml` **auto-kebaca** tiap `docker compose up` tanpa flag apa pun — jadi default sekarang = **Tahap 3**. Buat jalanin Tahap 1–2 (nginx polos, tanpa build modsec), override harus di-skip eksplisit:

| Mau jalanin | Command |
|-------------|---------|
| Tahap 3 (build + modsec) | `docker compose up -d` |
| Tahap 1–2 (nginx polos) | `docker compose -f docker-compose.yml up -d` |

### 3. Iterasi 1 — rule inline (smoke test)

Titik awal paling simpel: conf nginx + `main.conf` yang masih nempelin satu rule lewat `modsecurity_rules '...'`. Belum ada file rule terpisah, belum ada anomaly scoring. Cuma mau mastiin **engine-nya nyala dan bisa nge-block**.

**`conf/nginx/tahap-3-modsecurity.conf` (Iterasi 1):**

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

**`conf/nginx/modsec/main.conf` (Iterasi 1):**

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
| `modsecurity on` | Nyalain connector buat server ini. Request diteruskan ke libmodsecurity sebelum di-`proxy_pass` |
| `modsecurity_rules '...'` | Rule **inline** — cukup buat smoke test. Diganti `modsecurity_rules_file` di Iterasi 2 |
| `SecRuleEngine On` | Engine mode blocking. Default-nya `Off` kalau gak diset |
| `SecRule ARGS:test "@streq attack" ...` | Kalau parameter `test` isinya persis `attack` → `deny` dengan `403` di phase 1 (request headers, query string udah kebaca) |
| `id:100001` | Range custom rule `100000–199999` |

Rule smoke test ditulis tanpa tanda kutip di `msg` biar gak bentrok sama kutip tunggal pembungkus `modsecurity_rules`.

### 4. Build & jalanin

```bash
# dari Mac
cd Infrastructure/waf/modsecurity-scratch
scp -r Dockerfile docker-compose.yml docker-compose.override.yml conf anang@10.10.10.5:/data/waf/scratch/

# di VM
cd /data/waf/scratch
sed -i 's/^NGINX_CONF=.*/NGINX_CONF=tahap-3-modsecurity.conf/' .env
docker compose build                       # SEKALI, lama (compile libmodsecurity + connector), override auto-kebaca
docker compose up -d --force-recreate
docker exec waf-scratch nginx -t
```

`docker compose build` cuma perlu sekali — image `waf-scratch:...` ke-cache. Habis itu tiap ganti config cukup `up -d --force-recreate` (gak build ulang). Semua command **tanpa `-f`** → override auto-kebaca (Tahap 3). Buat balik ke Tahap 1–2: ganti `NGINX_CONF`, terus `docker compose -f docker-compose.yml up -d --force-recreate`.

Kalau build gagal, scroll ke error **pertama** di output `docker compose build`, bukan yang terakhir. Biasanya dependency `-dev` yang kurang (`configure: error: ... not found`).

---

## Verifikasi — Iterasi 1 ✅ (live 2026-10-22)

### 1. Build sukses

Image ke-build mulus (compile ±11 menit di VM 2 core), tag `waf-scratch:nginx-1.28.0-modsec-3.0.17` jadi. Container `Up` setelah `up -d --force-recreate`, `nginx -t` lolos.

### 2. Smoke test — block confirmed

Akses dari Mac (`192.168.43.193`) lewat NAT pfSense (`http://192.168.43.100`):

| Uji | Hasil |
|-----|-------|
| `GET /` | `302` (redirect normal DVWA) |
| `GET /login.php` | `200` |
| `GET /login.php?test=attack` | **`403`** — diblok ModSecurity |

**`access.log`:**

```
192.168.43.193 - - [22/Oct/2026:08:08:06 +0000] "GET / HTTP/1.1" 302 0 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:158.0) Gecko/20100101 Firefox/158.0"
192.168.43.193 - - [22/Oct/2026:08:08:06 +0000] "GET /login.php HTTP/1.1" 200 606 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:158.0) Gecko/20100101 Firefox/158.0"
192.168.43.193 - - [22/Oct/2026:08:08:13 +0000] "GET /login.php?test=attack HTTP/1.1" 403 146 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:158.0) Gecko/20100101 Firefox/158.0"
```

**`error.log` (bukti definitif rule yang nge-block, bukan sekadar status 403):**

```
2026/10/22 08:08:13 [error] 35#35: *7 [client 192.168.43.193] ModSecurity: Access denied with code 403 (phase 1). Matched "Operator `StrEq' with parameter `attack' against variable `ARGS:test' (Value: `attack' ) [file "<<reference missing or not informed>>"] [line "3"] [id "100001"] [rev ""] [msg "tahap3-smoke-test"] ... [hostname "192.168.43.100"] [uri "/login.php"] [unique_id "17926564939.085935"] ..., client: 192.168.43.193, server: _, request: "GET /login.php?test=attack HTTP/1.1", host: "192.168.43.100"
```

![Smoke test `?test=attack` → 403](../asset/modsecurity-scratch/tahap-3-smoke-test-attack-403.png)

Catatan temuan:
- `[id "100001"]` + `[msg "tahap3-smoke-test"]` → yang nge-block beneran rule kita, bukan 403 dari sumber lain. Engine ON + connector `.so` ke-load + rule kebaca → **mesin nyala confirmed.**
- `[file "<<reference missing or not informed>>"] [line "3"]` → kolom `file` kosong karena rule-nya **inline** (`modsecurity_rules`), belum dari file. Di Iterasi 2 (`modsecurity_rules_file`) kolom ini keisi nama file.
- `client 192.168.43.193` = IP attacker asli kebawa bener (penting buat ingest Wazuh nanti).

---

## Keputusan: pindah ke file-based (Iterasi 2)

Setelah mesin kebukti nyala, config dirombak dari inline ke **file-based**. Alasannya:

1. **Lebih terorganisir** — rule kepisah per kategori di folder `rules/` (`rules-sqli.conf`, nanti `rules-xss.conf`, dll), gak numpuk di satu string inline.
2. **Update gak pusing** — edit rule cukup di file `rules/`, conf nginx utama gak disentuh. Dan karena file di-mount langsung (bukan via template envsubst), ganti rule bisa `nginx -s reload` **tanpa `--force-recreate`**.
3. **Hilang masalah kutip** — rule gak lagi kebungkus `modsecurity_rules '...'`, jadi `msg:'...'` + regex special char aman ditulis normal.
4. **Mendekati real case** — ini persis cara CRS di-load (engine config + `Include rules/*.conf` + anomaly scoring). Jadi pondasi yang sama buat Tahap 5 (CRS manual) nanti.

> Catatan scope: file-based + anomaly scoring ini sebenernya udah nyerempet materi **Tahap 4** (`04-modsecurity-basic-rules.md`). Diputusin ditaruh di sini sebagai kelanjutan natural dari build; kalau nanti kerasa kegedean, bisa dipindah ke doc `04-`.

---

## Step-by-Step — Iterasi 2 (file-based + kerangka anomaly scoring)

✅ **Config di bawah udah di-deploy & kebukti live 2026-10-23** (lihat Verifikasi Iterasi 2).

### 5. `tahap-3-modsecurity.conf` — ganti ke `modsecurity_rules_file`

`modsecurity on` tetep (directive nginx), `include` diganti `modsecurity_rules_file` yang nunjuk ke `main.conf`:

```nginx
        modsecurity on;
        modsecurity_rules_file /etc/nginx/modsec/main.conf;
```

> Penting: `modsecurity on` + `modsecurity_rules_file` itu directive **nginx** (di conf nginx). `SecRuleEngine`, `SecRule`, `SecAudit*`, `Include` itu directive **ModSecurity** (di dalam file yang ditunjuk). Jangan naro `modsecurity on` di `main.conf` → nginx bakal error `unknown directive`.

### 6. `conf/nginx/modsec/main.conf` — config engine + loader

```nginx
SecRuleEngine On

SecAuditEngine RelevantOnly
SecAuditLog /var/log/nginx/modsec_audit.log
SecAuditLogParts ABIJDEFHZ
SecAuditLogFormat JSON
SecAuditLogType Serial
SecAuditLogRelevantStatus "^(?:5|4(?!04))"
SecRequestBodyAccess On
SecRequestBodyLimit 13107200
SecRequestBodyNoFilesLimit 131072

SecDefaultAction "phase:1,pass,log,auditlog"
SecDefaultAction "phase:2,pass,log,auditlog"
SecAction "id:100900,phase:1,pass,nolog,t:none, \
    setvar:tx.critical_anomaly_score=5, \
    setvar:tx.error_anomaly_score=4, \
    setvar:tx.warning_anomaly_score=3, \
    setvar:tx.notice_anomaly_score=2, \
    setvar:tx.inbound_anomaly_score_threshold=5, \
    setvar:tx.outbound_anomaly_score_threshold=4, \
    setvar:tx.inbound_anomaly_score_pl1=0, \
    setvar:tx.blocking_paranoia_level=1, \
    setvar:tx.detection_paranoia_level=2"

Include /etc/nginx/modsec/rules/*.conf

SecRule TX:INBOUND_ANOMALY_SCORE_PL1 "@ge %{tx.inbound_anomaly_score_threshold}" \
    "id:100999,phase:2,deny,status:403,log, \
    msg:'Inbound Anomaly Score Exceeded (score %{tx.inbound_anomaly_score_pl1})'"
```

| Bagian | Fungsi |
|--------|--------|
| `SecAuditEngine RelevantOnly` + `SecAuditLogRelevantStatus "^(?:5|4(?!04))"` | Audit **cuma** transaksi status 4xx/5xx (kecuali 404) → request normal gak nyampah |
| `SecAuditLogFormat JSON` | Format JSON (butuh `libyajl` yang di-compile di Dockerfile) — konsisten sama stack CRS, enak di-ingest Wazuh (Tahap 6) |
| `SecRequestBodyAccess On` | Biar `REQUEST_BODY` kebaca → SQLi lewat POST body ikut ke-scan |
| `SecAction id:100900` (phase 1) | **Inisialisasi** tanpa syarat: nge-set skor severity (critical=5 … notice=2), threshold inbound/outbound, reset `pl1=0` + level paranoia |
| `Include .../rules/*.conf` | Tarik semua file rule deteksi dari folder `rules/` |
| `SecRule TX:INBOUND_ANOMALY_SCORE_PL1 "@ge ..."` (id 100999) | **Blocking eval**: kalau skor PL1 ≥ threshold → `deny` 403. Ini satu-satunya rule yang nge-block di model anomaly |

### 7. `conf/nginx/modsec/rules/rules-sqli.conf` — rule deteksi

```nginx
SecRule ARGS,ARGS_NAMES,REQUEST_HEADERS,REQUEST_BODY,REQUEST_HEADERS:User-Agent "@detectSQLi" \
    "id:100001, \
    phase:2, \
    block, \
    nolog, \
    auditlog, \
    status:403, \
    t:none,t:urlDecodeUni,t:lowercase, \
    msg:'SQL Injection Attack Detected', \
    severity:CRITICAL, \
    tag:'paranoia-level/1', \
    tag:'attack-sqli', \
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
```

Cara kerja model anomaly (beda sama direct-deny):

- **`@detectSQLi`** + `t:urlDecodeUni,t:lowercase` → deteksi pakai libinjection (bukan regex mentah kayak Tahap 2), tahan encoding.
- **`block`** → **bukan** block langsung; dengan `SecDefaultAction ... pass`, `block` efektifnya pass + **nyumbang skor** `tx.inbound_anomaly_score_pl1+= 5` (critical).
- Rule **`100999`** yang mutusin `deny` kalau skor ≥ threshold. Karena critical=5 dan threshold=5, **satu hit SQLi = langsung block**.
- **`_pl1`** di nama variabel = yang nentuin rule ini masuk ember **paranoia level 1** (bukan dari tag/severity). Severity nentuin **nilai** skor, `_plN` nentuin **ember**-nya.
- **`nolog,auditlog`** → gak nulis error.log, cuma audit log → error.log bersih, isinya cuma keputusan block dari `100999`.

### 8. Deploy Iterasi 2

File udah ada di VM dari Iterasi 1, tinggal sync yang berubah + recreate (build **gak perlu** ulang):

```bash
# dari Mac — sync file yang berubah
scp docker-compose.override.yml anang@10.10.10.5:/data/waf/scratch/
scp -r conf/nginx/tahap-3-modsecurity.conf conf/nginx/modsec \
    anang@10.10.10.5:/data/waf/scratch/conf/nginx/

# di VM
cd /data/waf/scratch
sudo chown 101:101 logs && sudo chmod 750 logs    # worker uid 101 bisa nulis audit log (ikut pola CRS, jangan 777)
docker compose up -d --force-recreate
docker exec waf-scratch nginx -t
```

---

## Verifikasi — Iterasi 2 ✅ (live 2026-10-23)

Deploy iter 2 (`--force-recreate`, **tanpa rebuild**) + test dari Mac (Firefox, `192.168.43.193`) ke DVWA via WAF `192.168.43.100`.

### 1. Config valid + engine load ✅

`nginx -t` ok, `Include /etc/nginx/modsec/rules/*.conf` kebaca, module `.so` ke-load (udah kebukti sejak Iterasi 1).

### 2. SQLi block (anomaly chain) ✅

| Uji | Hasil | Keterangan |
|-----|-------|------------|
| SQLi (`id=1' OR '1'='1`) | **403** ✅ | `100001` detect (+5) → `100999` deny |
| XSS (`<script>alert(1)</script>`) | **200 lolos** (alert jalan) | belum ada rule XSS — sesuai ekspektasi |

![SQLi `' OR '1'='1` → 403](../asset/modsecurity-scratch/tahap-3-iter-2-sqli-or-403.png)
![XSS `<script>` lolos 200](../asset/modsecurity-scratch/tahap-3-iter-2-xss-lolos.png)

access.log (attacker Mac `192.168.43.193`):

```
192.168.43.193 - - [23/Oct/2026:02:33:51 +0000] "GET /vulnerabilities/sqli/?id=1%27+OR+%271%27%3D%271&Submit=Submit HTTP/1.1" 403 146 ...
192.168.43.193 - - [23/Oct/2026:02:34:17 +0000] "GET /vulnerabilities/xss_r/?name=%3Cscript%3Ealert%281%29%3C%2Fscript%3E HTTP/1.1" 200 1489 ...
```

### 3. error.log — yang nge-block id `100999`, bukan `100001` ✅ *(ekspektasi, bukan bug)*

```
2026/10/23 02:33:51 [error] 35#35: *1 [client 192.168.43.193] ModSecurity: Access denied with code 403 (phase 2). Matched "Operator `Ge' with parameter `5' against variable `TX:INBOUND_ANOMALY_SCORE_PL1' (Value: `5')" [file ".../main.conf"] [line "28"] [id "100999"] [msg "Inbound Anomaly Score Exceeded (score 5)"] ... [uri "/vulnerabilities/sqli/"] ...
```

Yang muncul di error.log **id `100999`**, bukan `100001` — ini justru nandain anomaly model jalan benar: `100001` (`nolog,auditlog`) deteksi SQLi senyap + nambah skor, `100999` (`log`) yang ambil keputusan deny → dia yang ke error.log. Satu hit SQLi critical (5) = threshold (5) → langsung block.

### 4. Audit log JSON — permission uid 101 ✅ RESOLVED

`modsec_audit.log` kebuat & keisi (worker uid 101 bisa nulis). Fix permission ngikut stack CRS: `chown 101:101 logs` + `chmod 750 logs` di VM (non-`-R`, jaga integritas audit — **jangan** `chmod 777`).

Entri audit buat request 403 ngerekam **dua** message — jejak bukti lengkap:
- `ruleId 100001` `"detected SQLi using libinjection"` `[file ".../rules/rules-sqli.conf"]` → deteksi
- `ruleId 100999` `"Inbound Anomaly Score Exceeded (score 5)"` → keputusan block
- `client_ip 192.168.43.193` → IP attacker asli kebawa (bukan IP container `172.18.0.2`)

(XSS 200 gak ada entri audit — `SecAuditLogRelevantStatus "^(?:5|4(?!04))"` cuma log 4xx/5xx, sesuai.) Kosmetik: `"Server":"nginx\u0000"` di response header audit = null byte efek `server_tokens off`, gak ngaruh.

**Sisa yang belum fungsional di Tahap 3 (dilanjut di Tahap 4 → [`04-modsecurity-basic-rules.md`](./04-modsecurity-basic-rules.md)):**
- **Paranoia gating** — `tx.*_paranoia_level` baru dipake buat label. ✅ **Direalisasi di Tahap 4**: gerbang `skipAfter` + ember PL2 (XSS shadow) kebukti live.
- **Outbound** — `tx.outbound_anomaly_score_threshold` di-set tapi belum ada `SecResponseBodyAccess` + rule outbound.

---

## Pembanding sama Tahap 2

Payload yang lolos di Tahap 2 (`%3Cscript%3E`, `' OR '1'='1`) jadi bahan uji di Iterasi 2: `@detectSQLi` + transformation harusnya nangkep yang regex mentah Tahap 2 lolosin. Hasil adu lengkapnya (SQLi/XSS/traversal) dilanjut di Tahap 4.
