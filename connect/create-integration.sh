#!/usr/bin/env bash
# Create a Connect "HashiCorp Vault" integration and optionally associate it
# with a content item.
#   CONNECT_SERVER, CONNECT_API_KEY  required (administrator API key)
#   VAULT_ADDR                       required, no trailing slash
#   VAULT_NAMESPACE                  default "". Must be sent even when empty:
#                                    Connect rejects a config without the key.
#   CONTENT_GUID                     optional; associate the new integration with it
set -euo pipefail
: "${CONNECT_SERVER:?}" "${CONNECT_API_KEY:?}" "${VAULT_ADDR:?}"
VAULT_NAMESPACE="${VAULT_NAMESPACE-}"
AUTH_PATH="${AUTH_PATH:-jwt-posit-connect}"
ROLE="${ROLE:-connect}"
SUBJECT="${SUBJECT:-connect}"
NAME="${NAME:-HashiCorp Vault}"
api() { curl -fsS -H "Authorization: Key ${CONNECT_API_KEY}" -H 'Content-Type: application/json' "$@"; }

body=$(python3 -I -c 'import json,sys; a=sys.argv[1:]; print(json.dumps({"template":"vault","name":a[0],
  "description":"Workload identity login to Vault","config":{"vault_addr":a[1],"vault_namespace":a[2],
  "auth_path":a[3],"role":a[4],"subject":a[5]}}))' \
  "$NAME" "$VAULT_ADDR" "$VAULT_NAMESPACE" "$AUTH_PATH" "$ROLE" "$SUBJECT")
guid=$(api -X POST "${CONNECT_SERVER%/}/__api__/v1/oauth/integrations" -d "$body" |
  python3 -I -c 'import json,sys; print(json.load(sys.stdin)["guid"])')
echo "integration ${guid}"

if [ -n "${CONTENT_GUID:-}" ]; then
  api -X PUT "${CONNECT_SERVER%/}/__api__/v1/content/${CONTENT_GUID}/oauth/integrations/associations" \
    -d "[{\"oauth_integration_guid\":\"${guid}\"}]"
  echo "associated with content ${CONTENT_GUID} (restart its processes to pick it up)"
fi
