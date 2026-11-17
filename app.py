import datetime
import json
import os
import re
import warnings

import hvac
import requests
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from hvac.exceptions import Forbidden, InvalidPath, VaultError

app = FastAPI()

# Defaults for the form. Set these as content environment variables (Vars) in
# Connect to point the demo at a different secret without changing code.
DEFAULTS = {
    "mount": os.environ.get("DEMO_SECRET_MOUNT", "secret"),
    "path": os.environ.get("DEMO_SECRET_PATH", "connect/demo"),
    "key": os.environ.get("DEMO_SECRET_KEY", "value"),
}

# One or more "/"-separated segments of safe characters. "." and ".." are
# rejected separately so a path cannot step outside the KV mount's API.
PATH_RE = re.compile(r"^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$")
KEY_RE = re.compile(r"^[A-Za-z0-9_.-]*$")

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
        for k in (
            "type",
            "policies",
            "ttl",
            "creation_ttl",
            "renewable",
            "meta",
            "display_name",
            "path",
        )
    }


def valid_path(value):
    return bool(PATH_RE.match(value)) and all(
        seg not in (".", "..") for seg in value.split("/")
    )


def error(status, message):
    return JSONResponse(status_code=status, content={"error": message})


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
  form { display:grid; grid-template-columns: 140px 1fr 2fr; gap:12px 14px; align-items:end; margin-bottom:18px; }
  label { display:flex; flex-direction:column; gap:6px; font-size:.85rem; color:var(--muted); }
  input { font: inherit; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size:.92rem;
          padding:9px 10px; border:1px solid var(--line); border-radius:6px; color:var(--ink); }
  .hint { grid-column: 1 / -1; font-size:.82rem; color:var(--muted); margin-top:-4px; }
  button { font-size:1rem; padding:12px 22px; border:0; border-radius:8px; background:var(--accent); color:#fff; cursor:pointer; }
  button:disabled { opacity:.6; cursor:progress; }
  .secret { margin-top:20px; padding:18px 20px; border-radius:8px; border:1px solid #b7dfc4; background:#eef8f1;
            font-size:1.35rem; font-weight:600; color:var(--ok); display:none; white-space:pre-wrap; word-break:break-word; }
  .secret.object { font-size:.95rem; font-weight:500; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  .error { margin-top:20px; padding:14px 18px; border-radius:8px; border:1px solid #f0b4b4; background:#fdf1f1; color:#a12a2a; display:none; }
  dl { display:grid; grid-template-columns: 190px 1fr; gap:8px 16px; margin:0; font-size:.92rem; }
  dt { color:var(--muted); }
  dd { margin:0; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; word-break: break-all; }
  h2 { font-size:1rem; margin:0 0 14px; }
  .role { display:inline-block; margin:0 0 14px; padding:4px 12px; border-radius:999px; font-size:.85rem;
          background:#e8eff6; color:var(--accent); border:1px solid #c9d8e8; }
  .role code { font-weight:600; }
</style>
</head>
<body>
<main>
  <h1>HashiCorp Vault secret demo</h1>
  <div class="role" id="role"></div>
  <p class="lede">This content has no Vault credentials of its own. When it starts, Connect signs a short-lived
  identity token, <code>connect-session</code> exchanges it at Vault's JWT auth method, and the content
  receives <code>VAULT_TOKEN</code>.</p>

  <div class="card">
    <form id="form">
      <label>KV v2 mount<input id="mount" name="mount" autocomplete="off" spellcheck="false"></label>
      <label>Secret path<input id="path" name="path" autocomplete="off" spellcheck="false"></label>
      <label>Key (empty = all keys)<input id="key" name="key" autocomplete="off" spellcheck="false"></label>
      <div class="hint">Reads <code id="preview"></code>. The token's Vault policy decides what is allowed.</div>
    </form>
    <button id="get" type="submit" form="form">Retrieve secret from Vault</button>
    <div class="secret" id="value"></div>
    <div class="error" id="error"></div>
  </div>

  <div class="card" id="details" style="display:none">
    <h2>Where it came from</h2>
    <dl id="meta"></dl>
  </div>
</main>
<script id="defaults" type="application/json">__DEFAULTS__</script>
<script>
const defaults = JSON.parse(document.getElementById("defaults").textContent);
const $ = (id) => document.getElementById(id);
const esc = (v) => String(v).replace(/&/g, "&amp;").replace(/</g, "&lt;");
for (const k of ["mount", "path", "key"]) $(k).value = defaults[k];
$("role").innerHTML = defaults.role
  ? `Vault role <code>${esc(defaults.role)}</code> (from this content's Vault integration)`
  : "No Vault integration attached";
const preview = () => { $("preview").textContent = `${$("mount").value}/data/${$("path").value}`; };
["mount", "path"].forEach((k) => $(k).addEventListener("input", preview));
preview();

$("form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const btn = $("get"), value = $("value"), err = $("error");
  btn.disabled = true; value.style.display = "none"; err.style.display = "none";
  const q = new URLSearchParams({ mount: $("mount").value, path: $("path").value, key: $("key").value });
  try {
    const resp = await fetch("secret?" + q);  // relative: content is served under /content/<guid>/
    const body = await resp.json();
    if (!resp.ok) throw new Error(body.error || resp.statusText);
    const isObject = typeof body.value === "object";
    value.textContent = isObject ? JSON.stringify(body.value, null, 2) : body.value;
    value.className = "secret" + (isObject ? " object" : "");
    value.style.display = "block";
    const rows = [
      ["Vault address", body.vault_addr],
      ["Secret path", body.path + (body.key ? `  [${body.key}]` : "")],
      ["Secret version", body.version],
      ["Secret created", body.created_time],
      ["Vault role", (body.token.meta || {}).role || "?"],
      ["Login path", body.token.path],
      ["Token policies", body.token.policies.join(", ")],
      ["Token TTL remaining", body.token.ttl + " s of " + body.token.creation_ttl + " s"],
      ["Read at", body.read_at],
    ];
    $("meta").innerHTML = rows.map(([k, v]) => `<dt>${k}</dt><dd>${esc(v)}</dd>`).join("");
    $("details").style.display = "block";
  } catch (e) {
    err.textContent = e.message;
    err.style.display = "block";
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
    # Embed the defaults as JSON; "</" is escaped so a value cannot close the script tag.
    page_data = {**DEFAULTS, "role": os.environ.get("CONNECT_VAULT_ROLE", "")}
    data = json.dumps(page_data).replace("</", "<\\/")
    return PAGE.replace("__DEFAULTS__", data)


@app.get("/secret")
def secret(
    mount: str = DEFAULTS["mount"],
    path: str = DEFAULTS["path"],
    key: str = DEFAULTS["key"],
):
    mount, path, key = mount.strip().strip("/"), path.strip().strip("/"), key.strip()
    if not valid_path(mount):
        return error(
            400,
            "Mount must be one or more path segments of letters, digits, '_', '-' or '.'.",
        )
    if not valid_path(path):
        return error(
            400,
            "Path must be one or more path segments of letters, digits, '_', '-' or '.'.",
        )
    if not KEY_RE.match(key):
        return error(400, "Key may contain only letters, digits, '_', '-' and '.'.")

    client = vault_client()
    full = f"{mount}/data/{path}"
    try:
        resp = client.secrets.kv.v2.read_secret_version(
            mount_point=mount, path=path, raise_on_deleted_version=True
        )
    except Forbidden:
        try:
            policies = ", ".join(token_summary(client)["policies"])
        except VaultError:
            policies = "unknown"
        return error(
            403, f"Vault denied reading {full}. This token's policies: {policies}."
        )
    except InvalidPath:
        return error(404, f"No secret at {full} (or {mount}/ is not a KV v2 mount).")
    except (VaultError, requests.RequestException) as e:  # surface to the demo page
        return error(502, f"Vault read of {full} failed: {type(e).__name__}: {e}")

    data = resp["data"]["data"] or {}
    if key:
        if key not in data:
            keys = ", ".join(sorted(k for k in data if k)) or "none"
            return error(404, f"Key '{key}' not found at {full}. Keys there: {keys}.")
        value = data[key]
    else:
        value = data

    return {
        "value": value,
        "path": f"{mount}/{path}",
        "key": key,
        "version": resp["data"]["metadata"]["version"],
        "created_time": resp["data"]["metadata"]["created_time"],
        "vault_addr": os.environ.get("VAULT_ADDR"),
        "token": token_summary(client),
        "read_at": datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
    }


@app.get("/status")
def status():
    env = {k: os.environ.get(k) for k in VARS}
    if env["VAULT_TOKEN"]:
        env["VAULT_TOKEN"] = f"<set, {len(env['VAULT_TOKEN'])} chars>"
    out = {"pid": os.getpid(), "env": env, "defaults": DEFAULTS}

    # Publisher example from the admin guide, verbatim.
    client = hvac.Client()
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        try:
            response = client.secrets.kv.v2.read_secret_version(path="connect/database")
            out["guide_example_secret_keys"] = sorted(response["data"]["data"].keys())
        except VaultError as e:  # e.g. this content's role can't read connect/*
            out["guide_example_error"] = f"{type(e).__name__}: {e}"
    out["guide_example_warnings"] = [str(x.message) for x in w]
    out["token"] = token_summary(client)
    return out
