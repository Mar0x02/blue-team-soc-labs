# n8nio/n8n:latest base-nya "Docker Hardened Image" (Alpine yang di-strip termasuk apk-nya
# sendiri) — apk add langsung di atas base itu gak bisa (apk: not found). Fix-nya multi-stage:
# install python3 di stage Alpine biasa (masih punya apk) ke direktori terpisah, baru di-copy
# ke image n8n yang hardened. Sudah divalidasi: python3 jalan normal, n8n tetap boot & healthy.
FROM alpine:3.24 AS python-builder
RUN mkdir -p /python-root && \
    apk add --no-cache --initdb -p /python-root \
      -X https://dl-cdn.alpinelinux.org/alpine/v3.24/main \
      -U --allow-untrusted python3

FROM n8nio/n8n:latest
USER root
COPY --from=python-builder /python-root/usr /usr
COPY --from=python-builder /python-root/lib /lib
USER node
