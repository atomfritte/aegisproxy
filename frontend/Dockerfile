# syntax=docker/dockerfile:1.7
# AegisProxy web console as a standalone static site (nginx, non-root, read-only root fs capable).
#   docker build -t aegisproxy/console:2.1.0 frontend/
# Runtime configuration (environment):
#   AEGIS_API_BASE_URL   API origin when it differs from the console origin, e.g. https://aegis-api.corp.example
#   AEGIS_API_UPSTREAM   alternatively: reverse-proxy /api/ to this upstream (same-origin), e.g. http://control-plane:8081
FROM node:24-alpine AS build
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build

FROM nginxinc/nginx-unprivileged:1.29-alpine
COPY --from=build /src/dist /usr/share/nginx/html
COPY docker/nginx.conf /etc/nginx/conf.d/default.conf
COPY docker/40-aegis-config.sh /docker-entrypoint.d/40-aegis-config.sh
USER root
# Patch the base image and drop tools the static console never needs (smaller attack surface).
RUN apk upgrade --no-cache \
 && apk del --no-cache curl 2>/dev/null || true
RUN rm -f /usr/share/nginx/html/config.js && chmod 0755 /docker-entrypoint.d/40-aegis-config.sh
USER 101
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s CMD wget -qO- http://127.0.0.1:8080/healthz >/dev/null || exit 1
