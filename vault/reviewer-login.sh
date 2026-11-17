#!/usr/bin/env bash
# Optional: a userpass login for reviewing the configuration in the
# Vault UI without handing out the root token. It can read everything and
# edit only the demo secret (secret/connect/demo).
#   REVIEWER_USER      default: reviewer
#   REVIEWER_PASSWORD  required; read from the environment so it stays out of argv history.
set -euo pipefail
REVIEWER_USER="${REVIEWER_USER:-reviewer}"
: "${REVIEWER_PASSWORD:?set REVIEWER_PASSWORD}"

vault policy write reviewer - <<'POLICY'
# Read and list everything an ACL policy can grant. sudo-only endpoints stay closed.
path "*" {
  capabilities = ["read", "list"]
}
POLICY

vault policy write demo-editor - <<'POLICY'
# Edit the demo secret shown by the app, so a demo can change it live.
path "secret/data/connect/demo" {
  capabilities = ["create", "update", "patch", "read"]
}
path "secret/metadata/connect/demo" {
  capabilities = ["read", "list"]
}
POLICY

vault auth list -format=json | grep -q '"userpass/"' || vault auth enable userpass
# password=- makes the CLI read the value from stdin. (vault login does not
# support password=-; log in through the UI or the HTTP API instead.)
printf '%s' "${REVIEWER_PASSWORD}" |
  vault write "auth/userpass/users/${REVIEWER_USER}" password=- \
    token_policies=reviewer,demo-editor token_ttl=8h >/dev/null
echo "Created userpass user ${REVIEWER_USER} with policies reviewer, demo-editor"
