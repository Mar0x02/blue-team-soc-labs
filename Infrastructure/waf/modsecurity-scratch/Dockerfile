ARG NGINX_VERSION=1.28.0

FROM nginx:${NGINX_VERSION} AS builder

ARG NGINX_VERSION
ARG MODSEC_VERSION=v3.0.17
ARG CONNECTOR_VERSION=v1.0.4

RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates wget build-essential autoconf automake libtool pkgconf libpcre2-dev libxml2-dev libyajl-dev libcurl4-openssl-dev liblmdb-dev zlib1g-dev libssl-dev

WORKDIR /src

RUN git clone --depth 1 -b ${MODSEC_VERSION} --recursive https://github.com/owasp-modsecurity/ModSecurity.git && cd ModSecurity && ./build.sh && ./configure --with-pcre2 --disable-doxygen-doc --disable-examples && make -j"$(nproc)" && make install

RUN git clone --depth 1 -b ${CONNECTOR_VERSION} https://github.com/owasp-modsecurity/ModSecurity-nginx.git && wget -q https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz && tar xzf nginx-${NGINX_VERSION}.tar.gz && cd nginx-${NGINX_VERSION} && ./configure --with-compat --add-dynamic-module=/src/ModSecurity-nginx && make modules

FROM nginx:${NGINX_VERSION}

ARG NGINX_VERSION

RUN apt-get update && apt-get install -y --no-install-recommends libxml2 libyajl2 libcurl4 liblmdb0 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/modsecurity/lib /usr/local/modsecurity/lib/
COPY --from=builder /src/nginx-${NGINX_VERSION}/objs/ngx_http_modsecurity_module.so /usr/lib/nginx/modules/
COPY --from=builder /src/ModSecurity/unicode.mapping /etc/nginx/modsec/unicode.mapping
COPY --from=builder /src/ModSecurity/modsecurity.conf-recommended /etc/nginx/modsec/modsecurity.conf-recommended