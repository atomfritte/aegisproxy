# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
# AegisProxy web console as a standalone static site (nginx, non-root, read-only root fs capable).
#   docker build -t ghcr.io/atomfritte/aegisproxy-console:v3.0.0 frontend/   (or: make images)
# Runtime configuration (environment):
#   AEGIS_API_BASE_URL   API origin when it differs from the console origin, e.g. https://aegis-api.corp.example
#   AEGIS_API_UPSTREAM   alternatively: reverse-proxy /api/ to this upstream (same-origin), e.g. http://control-plane:8081
# Base images are pinned by digest (tag kept for readability; Dependabot updates both).
FROM node:24-alpine@sha256:06d7adf3e0ef61a13f1d28682726366f97a15aa1888c934d3ecec86c33918b53 AS build
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build

FROM nginxinc/nginx-unprivileged:1.31-alpine@sha256:b5047b9b76845eac124358373c6852377c52e4b05834a47647e955dd91cb8f1e
COPY --from=build /src/dist /usr/share/nginx/html
COPY docker/nginx.conf /etc/nginx/conf.d/default.conf
COPY docker/40-aegis-config.sh /docker-entrypoint.d/40-aegis-config.sh
USER root
# Patch the base image and drop tools the static console never needs (smaller attack surface).
RUN apk upgrade --no-cache \
 && { apk del --no-cache curl 2>/dev/null || true; }
RUN rm -f /usr/share/nginx/html/config.js && chmod 0755 /docker-entrypoint.d/40-aegis-config.sh
USER 101
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s CMD wget -qO- http://127.0.0.1:8080/healthz >/dev/null || exit 1
