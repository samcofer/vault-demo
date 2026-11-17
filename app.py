import datetime
import os
import warnings

import hvac
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse

app = FastAPI()

SECRET_MOUNT = "secret"
SECRET_PATH = "connect/demo"

VARS = [
    "VAULT_ADDR",
    "VAULT_NAMESPACE",
    "VAULT_TOKEN",
    "CONNECT_VAULT_INTEGRATION_GUID",
    "CONNECT_VAULT_TOKEN_URL",
    "CONNECT_VAULT_ROLE",
]


def vault_client():
    # VAULT_ADDR and VAULT_TOKEN come from the Connect Vault integration.
    # hvac does not read VAULT_NAMESPACE from the environment, so pass it.
    return hvac.Client(namespace=os.environ.get("VAULT_NAMESPACE") or None)


def token_summary(client):
    look = client.auth.token.lookup_self()["data"]
    return {
        k: look.get(k)
        for k in ("type", "policies", "ttl", "creation_ttl", "renewable", "meta", "display_name", "path")
    }


PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Vault secret demo</title>
<style>
  :root { --ink:#1f2933; --muted:#616e7c; --line:#d9e2ec; --accent:#447099; --ok:#2f7d4a; --bg:#f5f7fa; }
  * { box-sizing: border-box; }
  body { margin:0; font-family: system-ui, -apple-system, "Segoe UI", sans-serif; color:var(--ink); background:var(--bg); }
  main { max-width: 760px; margin: 48px auto; padding: 0 24px; }
  h1 { font-size: 1.6rem; margin: 0 0 6px; }
  p.lede { color: var(--muted); margin: 0 0 28px; line-height: 1.5; }
  .card { background:#fff; border:1px solid var(--line); border-radius:10px; padding:24px; margin-bottom:20px; }
  button { font-size:1rem; padding:12px 22px; border:0; border-radius:8px; background:var(--accent); color:#fff; cursor:pointer; }
  button:disabled { opacity:.6; cursor:progress; }
  .secret { margin-top:20px; padding:18px 20px; border-radius:8px; border:1px solid #b7dfc4; background:#eef8f1;
            font-size:1.35rem; font-weight:600; color:var(--ok); display:none; }
  .error { margin-top:20px; padding:14px 18px; border-radius:8px; border:1px solid #f0b4b4; background:#fdf1f1; color:#a12a2a; display:none; }
  dl { display:grid; grid-template-columns: 190px 1fr; gap:8px 16px; margin:0; font-size:.92rem; }
  dt { color:var(--muted); }
  dd { margin:0; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; word-break: break-all; }
  h2 { font-size:1rem; margin:0 0 14px; }
</style>
</head>
<body>
<main>
  <h1>HashiCorp Vault secret demo</h1>
  <p class="lede">This content has no Vault credentials of its own. When it starts, Connect signs a short-lived
  identity token, <code>connect-session</code> exchanges it at Vault's JWT auth method, and the content
  receives <code>VAULT_TOKEN</code>.</p>

  <div class="card">
    <button id="get">Retrieve secret from Vault</button>
    <div class="secret" id="value"></div>
    <div class="error" id="error"></div>
  </div>

  <div class="card" id="details" style="display:none">
    <h2>Where it came from</h2>
    <dl id="meta"></dl>
  </div>
</main>
<script>
const btn = document.getElementById("get");
btn.addEventListener("click", async () => {
  btn.disabled = true;
  const value = document.getElementById("value"), error = document.getElementById("error");
  value.style.display = "none"; error.style.display = "none";
  try {
    const resp = await fetch("secret");  // relative: content is served under /content/<guid>/
    const body = await resp.json();
    if (!resp.ok) throw new Error(body.error || resp.statusText);
    value.textContent = body.value;
    value.style.display = "block";
    const rows = [
      ["Vault address", body.vault_addr],
      ["Secret path", body.path],
      ["Secret version", body.version],
      ["Secret created", body.created_time],
      ["Login path", body.token.path],
      ["Token policies", body.token.policies.join(", ")],
      ["Token TTL remaining", body.token.ttl + " s of " + body.token.creation_ttl + " s"],
      ["Read at", body.read_at],
    ];
    document.getElementById("meta").innerHTML = rows.map(
      ([k, v]) => `<dt>${k}</dt><dd>${String(v).replace(/</g, "&lt;")}</dd>`).join("");
    document.getElementById("details").style.display = "block";
  } catch (e) {
    error.textContent = "Vault read failed: " + e.message;
    error.style.display = "block";
  } finally {
    btn.disabled = false;
  }
});
</script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
def index():
    return PAGE


@app.get("/secret")
def secret():
    try:
        client = vault_client()
        resp = client.secrets.kv.v2.read_secret_version(
            mount_point=SECRET_MOUNT, path=SECRET_PATH, raise_on_deleted_version=True
        )
        return {
            "value": resp["data"]["data"]["value"],
            "path": f"{SECRET_MOUNT}/{SECRET_PATH}",
            "version": resp["data"]["metadata"]["version"],
            "created_time": resp["data"]["metadata"]["created_time"],
            "vault_addr": os.environ.get("VAULT_ADDR"),
            "token": token_summary(client),
            "read_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        }
    except Exception as e:  # surface Vault errors to the demo page
        return JSONResponse(status_code=502, content={"error": f"{type(e).__name__}: {e}"})


@app.get("/status")
def status():
    env = {k: os.environ.get(k) for k in VARS}
    if env["VAULT_TOKEN"]:
        env["VAULT_TOKEN"] = "<set, %d chars>" % len(env["VAULT_TOKEN"])
    out = {"pid": os.getpid(), "env": env}

    # Publisher example from the admin guide, verbatim.
    client = hvac.Client()
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        response = client.secrets.kv.v2.read_secret_version(path="connect/database")
    out["guide_example_warnings"] = [str(x.message) for x in w]
    out["guide_example_secret_keys"] = sorted(response["data"]["data"].keys())
    out["token"] = token_summary(client)
    return out
