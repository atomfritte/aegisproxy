#!/usr/bin/env sh
# Prints freshly generated AegisProxy secrets in .env format.
#   install -m 600 .env.example .env && ./scripts/gen-secrets.sh >> .env
# The .env file holds every secret of the deployment: keep it at mode 600. When the output is
# redirected into a file, group/other permissions are removed from it (or a warning is printed).
set -eu
umask 077
if [ -f /dev/stdout ]; then
    chmod go-rwx /dev/stdout 2>/dev/null ||
        echo "gen-secrets.sh: WARNING: could not restrict the output file; run chmod 600 on it" >&2
fi
rand() { openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
echo "AEGIS_JWT_SECRET=$(rand)"
echo "AEGIS_DATAPLANE_KEY=$(rand)"
echo "AEGIS_ENCRYPTION_KEY=$(rand)"
echo "AEGIS_DB_PASSWORD=$(rand)"
echo "AEGIS_TRUSTED_PROXY_SECRET=$(rand)"
