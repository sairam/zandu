<p align="center">
  <img src="assets/logo.svg" alt="Zandu" width="96" height="96">
</p>

<h1 align="center">Zandu</h1>

## Forwarder

Zandu Forwarder is a small, permission-aware API gateway for third-party APIs
whose only access control is an account-wide key, often combined with an IP
allowlist. Registrar APIs such as Dynadot and Namecheap are typical: a single
key can read DNS, but it can also transfer or delete every domain in the
account.

The forwarder runs on the allowlisted address and holds the upstream
credentials itself. Internal services call the forwarder instead of the API,
authenticate as a named client, and each request is forwarded only if one of
that client's policies allows it.

```
 client ──(client token / basic / JWT)──▶ forwarder ──(API key / basic / bearer / OAuth2)──▶ upstream API
                                            │
                                            ├─ authenticate client and source IP
                                            ├─ evaluate policies on method, path and parameters
                                            ├─ strip client credentials, inject upstream credentials
                                            └─ record the decision in the audit log
```

Highlights:

- **Fine-grained policies.** Allow or deny by HTTP method, path glob and
  parameter values from the query string and form-encoded bodies. For
  example, "`set_dns2` on `example.com` only".
- **Credentials stay in one place.** Upstream keys are injected by the
  forwarder and never handed to clients. Secrets can come from environment
  variables, files, a shared JSON secrets file, or HashiCorp Vault. They are
  resolved at request time, so you can rotate them without a restart.
- **Flexible authentication on both sides.** Clients can authenticate with
  forwarder-issued tokens (bearer, header or HTTP Basic) or with JWTs from
  any OIDC/OAuth2 issuer. Upstreams can authenticate with injected
  parameters or headers, HTTP Basic, a bearer token, or OAuth2 client
  credentials.
- **Admin UI.** Manage upstreams, policies, clients and JWT issuers, dry-run
  requests against policies, and watch an audit log of recent decisions.
- **Small footprint.** A single static binary with no external
  dependencies. Configuration is one JSON file.

### Quick start

```sh
go build -o bin/zandu-forwarder ./cmd/zandu-forwarder

export ZANDU_ADMIN_TOKEN="$(openssl rand -hex 24)"
export DYNADOT_API_KEY=...            # used by the Dynadot preset
./bin/zandu-forwarder -config forwarder.json
```

- Proxy: `http://localhost:8080`
- Admin UI: `http://127.0.0.1:8081` (sign in with `ZANDU_ADMIN_TOKEN`)

In the UI, open **Upstreams**, add the **Dynadot API3** or **Namecheap API**
preset, adjust the starter policies, then create a client under **Clients**.
The client's token is shown once.

With Docker:

```sh
docker build -t zandu-forwarder .
docker run -d --name zandu \
  -e ZANDU_ADMIN_TOKEN -e DYNADOT_API_KEY \
  -p 8080:8080 -p 127.0.0.1:8081:8081 \
  -v zandu-data:/data zandu-forwarder
```

### Calling an API through the forwarder

Requests are addressed as `/{upstream}/{path}`. Everything after the
upstream name is forwarded to the upstream's base URL.

```sh
# Dynadot: read DNS for example.com
curl -H "Authorization: Bearer $ZANDU_TOKEN" \
  "http://forwarder:8080/dynadot/api3.json?command=get_dns&domain=example.com"

# Namecheap: same idea, HTTP Basic with the client name as user
curl -u "cert-manager:$ZANDU_TOKEN" \
  "http://forwarder:8080/namecheap/xml.response?Command=namecheap.domains.dns.getHosts&SLD=example&TLD=com"
```

Clients never send the upstream key. Any client-supplied parameter with the
same name as an injected credential (compared case-insensitively) is
removed. Responses carry `X-Zandu-Decision: allow|deny`. Errors are JSON:
`401` for authentication, `403` for policy denials, `502` when the upstream
or its credentials are unavailable.

### Configuration

The configuration file (default `forwarder.json`) is created on first start
and is written by the admin UI. You can also edit it by hand: send `SIGHUP`
to reload it, and run `zandu-forwarder check -config <file>` to validate it.
Unknown fields are rejected. See [`examples/forwarder.json`](examples/forwarder.json)
for a complete example.

#### Upstreams

```json
{
  "name": "namecheap",
  "base_url": "https://api.namecheap.com",
  "inject": {
    "query":   { "ApiUser": "env:NC_USER", "ApiKey": "vault:secret/data/namecheap#api_key" },
    "headers": { "X-Api-Version": "2" }
  },
  "auth": { "type": "oauth2_client_credentials", "token_url": "...", "client_id": "...", "client_secret": "vault:..." },
  "timeout_seconds": 30
}
```

`inject` adds parameters and headers to every forwarded request. `auth` adds
a standard scheme on top:

| `auth.type`                 | Fields                                                                              |
| --------------------------- | ----------------------------------------------------------------------------------- |
| `basic`                     | `username`, `password`                                                              |
| `bearer`                    | `token`                                                                             |
| `oauth2_client_credentials` | `token_url`, `client_id`, `client_secret`, `scopes`, `audience`, `client_auth_in_body` |

OAuth2 access tokens are cached and refreshed shortly before they expire, or
right away when the upstream answers `401`.

#### Policies

A policy is a named list of rules for one upstream:

```json
{
  "name": "dynadot-dns-example-com",
  "upstream": "dynadot",
  "rules": [
    { "effect": "allow", "methods": ["GET"], "path": "/api3.*",
      "params": { "command": ["get_dns", "set_dns2"], "domain": ["example.com", "*.example.com"] } },
    { "effect": "deny", "params": { "domain*": ["*.internal"] } }
  ]
}
```

Rule semantics:

- A request is **denied by default**. A matching `deny` rule always wins over
  any `allow` rule.
- `methods`: empty means any method. `path`: a glob where `*` matches within
  one segment and `**` matches any number of segments.
- `params` maps a parameter name, or a name glob such as `domain*`, to value
  globs (`*`, `?`).
  - In an **allow** rule, every value of every matching parameter must
    match, and a name without wildcards must be present. Repeated or
    differently-cased parameters can't be used to smuggle a second value
    past the check.
  - In a **deny** rule, a single matching value is enough.
- Matching is **case-insensitive** for paths, parameter names and values.
- Parameters are read from the query string and from
  `application/x-www-form-urlencoded` bodies. The forwarded request is
  exactly the one that was evaluated. Multipart bodies, malformed
  `Content-Type` headers and repeated `Content-Type` headers are rejected.
  JSON bodies are forwarded but not inspected.

Use **Test** in the admin UI (or `POST /api/evaluate`) to dry-run a request
against a client's policies.

#### Clients and incoming authentication

```json
{
  "name": "cert-manager",
  "policies": ["dynadot-dns-example-com"],
  "allowed_ips": ["10.0.0.0/8"],
  "identities": [{ "issuer": "corp-idp", "subject": "cert-manager" }]
}
```

A client can authenticate in any of these ways:

| Method       | How                                                              |
| ------------ | ---------------------------------------------------------------- |
| Token        | `Authorization: Bearer zfw_…` or `X-Zandu-Token: zfw_…`           |
| HTTP Basic   | user = client name, password = client token                      |
| JWT          | `Authorization: Bearer <jwt>` from a configured issuer           |

Tokens are generated by the forwarder and stored only as SHA-256 hashes.
Issue or rotate them in the UI, or generate one with
`zandu-forwarder token`.

JWT issuers are configured under `issuers`. Each issuer sets either a
`jwks_url` (RS256/384/512, PS256/384/512, ES256/384/512, EdDSA) or an
`hmac_secret` (HS256/384/512), never both. Tokens must carry `exp` and the
expected `iss`, and an `aud` from `audience` when one is configured. The
claim named by `subject_claim` (default `sub`; `client_id` or `azp` are
common for client-credentials tokens) is mapped to a client through its
`identities`. This works with any OAuth2 authorization server that issues
JWT access tokens, for example Keycloak, Auth0, Okta or Entra ID.

### Secrets

Any credential in the configuration can be a literal or a reference:

| Reference                          | Source                                                    |
| ---------------------------------- | --------------------------------------------------------- |
| `env:NAME`                         | Environment variable                                      |
| `file:/path`                       | Whole file, trimmed                                       |
| `file:/path/secrets.json#a.b`      | String at a dotted key of a JSON file                     |
| `vault:secret/data/app#field`      | Field of a HashiCorp Vault (or OpenBao) secret, KV v1 or v2 |

References are resolved when a request is forwarded and cached for
`-secret-ttl` (default one minute). If a refresh fails, the last good value
is used. With nothing cached, the request fails with `502` rather than
being sent without credentials. The JSON-file form lets the forwarder share
one secrets file with other components, such as an nginx/OpenResty Lua
layer, that are rotated by the same process.

Vault is enabled when `VAULT_ADDR` is set and authenticates with one of:

- `VAULT_TOKEN`
- `VAULT_TOKEN_FILE` (for example, a Vault Agent sink; re-read when Vault
  rejects the token)
- `VAULT_ROLE_ID` and `VAULT_SECRET_ID` for AppRole (`VAULT_APPROLE_MOUNT`
  defaults to `approle`)

`VAULT_NAMESPACE` is honored.

In the admin UI, literal secrets are masked. **Check credentials** on an
upstream resolves its secrets and OAuth2 token without sending a request.

### Command line

```
zandu-forwarder [serve] [flags]   run the proxy and admin UI
zandu-forwarder check [flags]     validate the configuration file
zandu-forwarder token             print a new client token and its hash
```

| Flag               | Environment             | Default           |
| ------------------ | ----------------------- | ----------------- |
| `-config`          | `ZANDU_CONFIG`          | `forwarder.json`  |
| `-listen`          | `ZANDU_LISTEN`          | `:8080`           |
| `-admin-listen`    | `ZANDU_ADMIN_LISTEN`    | `127.0.0.1:8081`  |
| `-trusted-proxies` | `ZANDU_TRUSTED_PROXIES` | none              |
| `-secret-ttl`      |                         | `1m`              |
| `-audit-size`      |                         | `1000`            |

`ZANDU_ADMIN_TOKEN` (at least 16 characters) is required unless the admin
listener is disabled with `-admin-listen=''`.

### Deployment notes

- Run the forwarder on the address the upstream allowlists. Keep the admin
  listener on a private interface.
- Terminate TLS in front of the forwarder with nginx, Caddy or a load
  balancer. List those hops in `-trusted-proxies` so `allowed_ips` sees the
  real client address from `X-Forwarded-For`.
- Every decision is logged as a JSON line on stdout. The most recent ones
  are also shown in the admin UI. Upstream credentials are never logged.
- `GET /_zandu/healthz` on the proxy listener answers `ok` without
  authentication.

### Development

```sh
go test -race ./...
go vet ./...
```

The admin UI is plain HTML, CSS and JavaScript in `forwarder/ui`, embedded
into the binary at build time.
