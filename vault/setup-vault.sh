#!/usr/bin/env bash
# Configure Vault so Posit Connect content can log in with Connect-issued JWTs.
# Follows https://docs.posit.co/connect/admin/integrations/oauth-integrations/vault/
# with three additions: a KV v2 mount (absent outside -dev mode), a bounded token
# TTL, and the demo secrets the app reads.
#
# Requires: vault CLI, VAULT_ADDR, and VAULT_TOKEN with rights to manage auth
# methods, policies, and mounts.
#   CONNECT_SERVER_ADDRESS  required. Connect's iss claim: IdentityProvider.Issuer if set,
#                           otherwise Server.Address WITH its trailing slash.
set -euo pipefail

: "${CONNECT_SERVER_ADDRESS:?set to the Connect issuer, e.g. https://connect.example.org/}"
CONNECT_JWT_PATH="${CONNECT_JWT_PATH:-jwt-posit-connect}"
CONNECT_POLICY="${CONNECT_POLICY:-posit-connect-secrets}"
CONNECT_SUBJECT="${CONNECT_SUBJECT:-connect}"
TOKEN_TTL="${TOKEN_TTL:-24h}"
KV_MOUNT="${KV_MOUNT:-secret}"

# Vault rejects the config write below unless it can fetch this document.
curl -fsS "${CONNECT_SERVER_ADDRESS%/}/.well-known/openid-configuration" >/dev/null

vault secrets list -format=json | grep -q "\"${KV_MOUNT}/\"" ||
  vault secrets enable -path="${KV_MOUNT}" kv-v2

vault auth list -format=json | grep -q "\"${CONNECT_JWT_PATH}/\"" ||
  vault auth enable -path="${CONNECT_JWT_PATH}" -description="Posit Connect" jwt

vault write "auth/${CONNECT_JWT_PATH}/config" \
  oidc_discovery_url="${CONNECT_SERVER_ADDRESS}" \
  bound_issuer="${CONNECT_SERVER_ADDRESS}"

vault policy write "${CONNECT_POLICY}" - <<POLICY
path "${KV_MOUNT}/data/connect/*" {
  capabilities = ["read"]
}
POLICY

# Write the whole role every time: a partial write without role_type is treated
# as an "oidc" role and rejected.
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

vault kv put -mount="${KV_MOUNT}" connect/demo value="Here's the Secret Value 1234" >/dev/null
vault kv put -mount="${KV_MOUNT}" connect/database username=demo password=demo-not-a-real-secret >/dev/null

echo "Vault ready: auth path ${CONNECT_JWT_PATH}, role ${CONNECT_SUBJECT}, policy ${CONNECT_POLICY}"
