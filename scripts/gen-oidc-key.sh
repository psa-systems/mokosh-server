#!/usr/bin/env bash
#
# Generate an Ed25519 (PKCS#8 PEM) keypair for mokosh-auth's OIDC signing.
#
# Usage:
#   scripts/gen-oidc-key.sh                        # auto kid: key-YYYY-MM-DD
#   scripts/gen-oidc-key.sh prod-2026-q1           # explicit kid
#
# Outputs:
#   secrets/<kid>.pem        Ed25519 PKCS#8 PEM private key (chmod 600).
#   secrets/<kid>.pub.pem    Public key (chmod 644). Served via JWKS.
#
# After running, set MOKOSH_AUTH_JWT_ACTIVE_KID=<kid> in your env so the
# server signs new tokens with this key. Old public keys can stay in
# secrets/ until tokens signed by them have all expired (zero-downtime
# rotation).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SECRETS_DIR="${REPO_ROOT}/secrets"
KID="${1:-key-$(date -u +%Y-%m-%d)}"

if [[ ! "$KID" =~ ^[A-Za-z0-9._-]+$ ]]; then
    echo "error: kid must match [A-Za-z0-9._-]+" >&2
    exit 1
fi

mkdir -p "$SECRETS_DIR"

PRIV="${SECRETS_DIR}/${KID}.pem"
PUB="${SECRETS_DIR}/${KID}.pub.pem"

if [[ -e "$PRIV" || -e "$PUB" ]]; then
    echo "error: ${PRIV} or ${PUB} already exists. Refusing to overwrite." >&2
    exit 1
fi

# `openssl genpkey -algorithm ED25519` writes a PKCS#8 PEM private key,
# which is exactly what jsonwebtoken's `EncodingKey::from_ed_pem` expects.
openssl genpkey -algorithm ED25519 -out "$PRIV"
openssl pkey -in "$PRIV" -pubout -out "$PUB"

chmod 600 "$PRIV"
chmod 644 "$PUB"

echo "Generated:"
echo "  ${PRIV}  (private, 600)"
echo "  ${PUB}   (public,  644)"
echo
echo "Add or update in your environment / .env:"
echo "  MOKOSH_AUTH_JWT_ACTIVE_KID=${KID}"
echo "  MOKOSH_AUTH_JWT_PRIVATE_KEY_PATH=${PRIV}"
echo "  MOKOSH_AUTH_JWT_PUBLIC_KEYS_DIR=${SECRETS_DIR}"
