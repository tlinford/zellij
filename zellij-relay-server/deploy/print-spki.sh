#!/usr/bin/env bash
# Print the SPKI SHA-256 pin for the relay host's current Let's Encrypt leaf.
#
# This is the value the attach client pins on first use (TOFU). Run it to
# publish the pin out-of-band, to verify a client's stored pin, or to prepare
# a baked-in pin. The pin is over the SubjectPublicKeyInfo, so it survives a
# `certbot --reuse-key` renewal and only changes when the key rotates.
#
# Output format matches curl/HPKP: `sha256//<base64>`.
#
# Expects DOCKER_HOST to already be set (deploy.sh does this).
# Expects $PUBLIC_HOST to be exported (default relay.zellij.online).

set -euo pipefail

: "${PUBLIC_HOST:=relay.zellij.online}"

PROJECT_NAME="${COMPOSE_PROJECT_NAME:-zellij-relay}"
LETSENCRYPT_VOL="${PROJECT_NAME}_letsencrypt"

CERT_PATH="/etc/letsencrypt/live/${PUBLIC_HOST}/fullchain.pem"

PIN=$(docker run --rm -v "${LETSENCRYPT_VOL}:/etc/letsencrypt:ro" \
    --entrypoint sh certbot/certbot:latest -c "
        openssl x509 -in '${CERT_PATH}' -pubkey -noout \
          | openssl pkey -pubin -outform der \
          | openssl dgst -sha256 -binary \
          | openssl base64
    ")

echo "sha256//${PIN}"
