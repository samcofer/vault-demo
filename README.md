# vault-demo

A small FastAPI app that shows Posit Connect's
[HashiCorp Vault integration](https://docs.posit.co/connect/admin/integrations/oauth-integrations/vault/):
content reads a Vault secret with no Vault credentials of its own.

When the content process starts, Connect signs a short-lived identity token
(`aud=vault`), the Connect content supervisor (`connect-session`) exchanges it at
Vault's JWT auth method, and the process receives `VAULT_ADDR` and `VAULT_TOKEN`.

| Route | What it does |
|---|---|
| `/` | Demo page: **Retrieve secret from Vault** reads `secret/connect/demo` and shows the value plus where it came from (path, version, token policies, token TTL). |
| `/secret` | JSON behind the button. |
| `/status` | Diagnostics: the Vault-related environment (token redacted), the admin guide's `hvac` example run verbatim, and `lookup-self` on the token. |

Tested with Connect 2026.10.0 and Vault Community Edition 2.2.2.

## Set up

### 1. Vault

Needs the `vault` CLI, `VAULT_ADDR`, and an admin `VAULT_TOKEN`.
Vault must be able to reach Connect's OIDC discovery document.

```bash
CONNECT_SERVER_ADDRESS=https://connect.example.org/ ./vault/setup-vault.sh
```

`CONNECT_SERVER_ADDRESS` must equal Connect's `iss` claim: `IdentityProvider.Issuer` if set,
otherwise `Server.Address` **with** its trailing slash.

The script enables a KV v2 mount at `secret/` and a JWT auth method at `jwt-posit-connect/`,
writes the `posit-connect-secrets` policy and the `connect` role (24h tokens), and writes the
demo secrets. It is safe to re-run.

Optional, for showing the config in the Vault UI without the root token:

```bash
REVIEWER_PASSWORD='...' ./vault/reviewer-login.sh
```

This creates userpass user `reviewer`: read-only everywhere, and able to edit
`secret/connect/demo` so a demo can change the value live.

### 2. Connect integration

Needs an administrator API key.

```bash
CONNECT_SERVER=https://connect.example.org CONNECT_API_KEY=... \
VAULT_ADDR=https://vault.example.org ./connect/create-integration.sh
```

Set `VAULT_NAMESPACE` for HCP Vault or Vault Enterprise (`admin` on HCP Vault Dedicated).
On Community Edition leave it unset; the script sends `""`.
Through the dashboard, Community Edition can't save the form, because the Vault Namespace field is
required there. Through the API the key must be present: leaving it out is rejected with
`The config key vault_namespace is missing`.

### 3. Deploy the content

```bash
rsconnect deploy fastapi --title "Vault secret demo" .
```

Or deploy from Git: `manifest.json` is committed.
Then, in the content's **Settings > Runtime > Integrations**, add the Vault integration.
The token is minted when a process starts, so restart the content's processes after adding it.

## Things that bite

- **`hvac.Client()` ignores `VAULT_NAMESPACE`.** Pass `namespace=os.environ.get("VAULT_NAMESPACE")`
  or namespaced Vault returns permission errors. `vaultr` (R) reads it from the environment.
- **No `secret/` mount outside `-dev` mode.** Enable KV v2 before writing policies or secrets.
- **Token lifetime.** `VAULT_TOKEN` is obtained once per process and is neither renewed nor revoked.
  Without `token_ttl` on the role, tokens inherit the mount default (768h). Set a TTL longer than a
  process lives, and expect a process that outlives it to lose access.
- **Same-bundle redeploys keep running processes**, and their tokens. After changing the role, stop
  the content's processes to see a new token.
- **Role edits must include `role_type=jwt`.** A partial `vault write .../role/connect token_ttl=...`
  is treated as an `oidc` role and rejected (`'allowed_redirect_uris' must be set`).
  `setup-vault.sh` always writes the whole role.
- **Sealed Vault = content that won't start.** A failed Vault login at process start is fatal for the
  content.
