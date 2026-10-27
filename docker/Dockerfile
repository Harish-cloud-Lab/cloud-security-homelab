FROM nginxinc/nginx-unprivileged:stable-alpine
USER root
RUN apk upgrade --no-cache brotli-libs libcurl
COPY index.html /usr/share/nginx/html/index.html
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://localhost:8080/ || exit 1
USER nginx