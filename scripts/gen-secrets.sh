#!/usr/bin/env sh
# Prints freshly generated AegisProxy secrets in .env format.
#   ./scripts/gen-secrets.sh >> .env
set -eu
rand() { openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
echo "AEGIS_JWT_SECRET=$(rand)"
echo "AEGIS_DATAPLANE_KEY=$(rand)"
echo "AEGIS_ENCRYPTION_KEY=$(rand)"
echo "AEGIS_DB_PASSWORD=$(rand)"
