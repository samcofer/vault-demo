#!/usr/bin/env bash
# Configure Vault so Posit Connect content can log in with Connect-issued JWTs.
# Follows https://docs.posit.co/connect/admin/integrations/oauth-integrations/vault/
# with three additions: a KV v2 mount, a bounded token TTL, and the demo secrets
# the app reads.
#
# Requires: vault CLI, VAULT_ADDR, and VAULT_TOKEN with rights to manage auth
# methods, policies, and mounts.
#   CONNECT_SERVER_ADDRESS  required. Connect's iss claim: IdentityProvider.Issuer if set,
#                           otherwise Server.Address WITH its trailing slash.
#   CONNECT_SUBJECT         role name and the JWT sub it accepts (default: connect).
#                           Give each Connect integration its own subject and role.
#   CONNECT_POLICY          policy name (default: posit-connect-secrets)
#   SECRET_PREFIX           the role may read KV_MOUNT/SECRET_PREFIX/* (default: connect)
#   DEMO_VALUE              value written to SECRET_PREFIX/demo if it doesn't exist
#
# Second role with different permissions:
#   CONNECT_SUBJECT=connect-finance CONNECT_POLICY=posit-connect-finance \
#   SECRET_PREFIX=finance DEMO_VALUE="Finance-only Secret Value 5678" ./vault/setup-vault.sh
# Safe to re-run: existing mounts are kept and existing demo secrets are not overwritten.
set -euo pipefail

: "${CONNECT_SERVER_ADDRESS:?set to the Connect issuer, e.g. https://connect.example.org/}"
CONNECT_JWT_PATH="${CONNECT_JWT_PATH:-jwt-posit-connect}"
CONNECT_POLICY="${CONNECT_POLICY:-posit-connect-secrets}"
CONNECT_SUBJECT="${CONNECT_SUBJECT:-connect}"
TOKEN_TTL="${TOKEN_TTL:-24h}"
KV_MOUNT="${KV_MOUNT:-secret}"
SECRET_PREFIX="${SECRET_PREFIX:-connect}"
DEFAULT_DEMO_VALUE="Here's the Secret Value 1234"
DEMO_VALUE="${DEMO_VALUE:-$DEFAULT_DEMO_VALUE}"

# Fail early unless Connect's OIDC discovery document is reachable (Vault fetches it too).
curl -fsS "${CONNECT_SERVER_ADDRESS%/}/.well-known/openid-configuration" >/dev/null

# Enable a KV v2 secrets engine at ${KV_MOUNT}/ unless it is already mounted.
vault secrets list -format=json | grep -q "\"${KV_MOUNT}/\"" ||
  vault secrets enable -path="${KV_MOUNT}" kv-v2

# Enable the JWT auth method for Connect unless it is already enabled.
vault auth list -format=json | grep -q "\"${CONNECT_JWT_PATH}/\"" ||
  vault auth enable -path="${CONNECT_JWT_PATH}" -description="Posit Connect" jwt

# Trust Connect as the token issuer: keys come from its discovery document, iss must match.
vault write "auth/${CONNECT_JWT_PATH}/config" \
  oidc_discovery_url="${CONNECT_SERVER_ADDRESS}" \
  bound_issuer="${CONNECT_SERVER_ADDRESS}"

# Policy: content using this role may read secrets under ${KV_MOUNT}/${SECRET_PREFIX}/ and nothing else.
vault policy write "${CONNECT_POLICY}" - <<POLICY
path "${KV_MOUNT}/data/${SECRET_PREFIX}/*" {
  capabilities = ["read"]
}
POLICY

# Role: accept tokens with aud=vault and sub=${CONNECT_SUBJECT}; issue ${TOKEN_TTL} tokens with the policy.
# The whole role is written each time; a partial write without role_type is rejected.
vault write "auth/${CONNECT_JWT_PATH}/role/${CONNECT_SUBJECT}" - <<ROLE
{
  "role_type": "jwt",
  "token_policies": ["${CONNECT_POLICY}"],
  "bound_audiences": ["vault"],
  "bound_subject": "${CONNECT_SUBJECT}",
  "user_claim": "sub",
  "token_type": "service",
  "token_ttl": "${TOKEN_TTL}",
  "token_max_ttl": "${TOKEN_TTL}"
}
ROLE

# Demo secret for this role; skipped if it already exists.
vault kv get -mount="${KV_MOUNT}" "${SECRET_PREFIX}/demo" >/dev/null 2>&1 ||
  vault kv put -mount="${KV_MOUNT}" "${SECRET_PREFIX}/demo" value="${DEMO_VALUE}" >/dev/null

# Secret read by the admin guide's example on the /status page; skipped if it already exists.
vault kv get -mount="${KV_MOUNT}" connect/database >/dev/null 2>&1 ||
  vault kv put -mount="${KV_MOUNT}" connect/database username=demo password=demo-not-a-real-secret >/dev/null

echo "Vault ready: auth path ${CONNECT_JWT_PATH}, role ${CONNECT_SUBJECT} (sub=${CONNECT_SUBJECT}), policy ${CONNECT_POLICY} -> ${KV_MOUNT}/${SECRET_PREFIX}/*"
