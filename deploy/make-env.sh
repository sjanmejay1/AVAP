#!/bin/sh
# Create the server's .env for the public deployment, with fresh random
# secrets. Run once, from the repository root, on the server:
#
#   sh deploy/make-env.sh your-name.duckdns.org
#
# It never overwrites an existing .env, and the file is readable only by you.
set -eu

domain="${1:-}"
case "$domain" in
  "" | *[!a-zA-Z0-9.-]* | .* | *. )
    echo "Usage: sh deploy/make-env.sh your-name.duckdns.org" >&2
    exit 1
    ;;
esac

if [ -e .env ]; then
  echo ".env already exists; leaving it unchanged." >&2
  exit 1
fi

command -v openssl >/dev/null 2>&1 || {
  echo "openssl is required (sudo apt-get install -y openssl)." >&2
  exit 1
}

# A Fernet key is 32 random bytes in URL-safe base64.
fernet_key=$(openssl rand -base64 32 | tr '+/' '-_')

umask 077
cat > .env <<EOF
# Written by deploy/make-env.sh. Keep this file private; never commit it.
COMPOSE_FILE=docker-compose.yml:docker-compose.demo.yml:docker-compose.prod.yml

AVAP_DOMAIN=$domain
ENVIRONMENT=production

POSTGRES_PASSWORD=$(openssl rand -hex 24)
JWT_SECRET_KEY=$(openssl rand -hex 64)
APP_ENCRYPTION_KEY=$fernet_key
TRUSTED_PROXY_SECRET=$(openssl rand -hex 32)

# Targets visitors may scan. demo-web and demo-cache are the isolated demo
# containers; scanme.nmap.org is Nmap's public test host. Add hosts you own.
SCAN_TARGET_ALLOWLIST=demo-web,demo-cache,scanme.nmap.org

STORAGE_BACKEND=local
OPENROUTER_MODEL=openrouter/free
EOF

echo "Wrote .env for https://$domain"
