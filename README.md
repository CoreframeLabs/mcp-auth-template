# mcp-auth-template

**A secure remote Model Context Protocol server template.** Streamable HTTP
transport, OAuth 2.1, Client ID Metadata Documents, and constant-time credential
verification — with a mock authorization server so the whole flow runs on your
laptop with no external accounts.

[![CI](https://github.com/CoreframeLabs/mcp-auth-template/actions/workflows/ci.yml/badge.svg)](https://github.com/CoreframeLabs/mcp-auth-template/actions/workflows/ci.yml)

Most MCP servers today run over stdio on localhost with no authentication at
all. The moment one becomes *remote*, it needs a real authorization story. This
template is that story, built to be read: every security decision has a comment
explaining why, including the places where a defence is deliberately **not**
applied.

---

## Why this exists

AI-assisted development produces code that passes its tests and still ships
security holes, because tests assert behaviour and attackers exploit properties
tests never check. Three that recur:

- **Naive credential comparison.** `if (token === expected)` returns as soon as
  two bytes differ. That difference is measurable, and it turns a secret into
  something an attacker can learn a byte at a time rather than guess whole.
- **Secrets stored in recoverable form.** A leaked config file or `docker inspect`
  hands over working credentials.
- **Endpoints that answer questions they were not asked.** A token endpoint that
  responds faster for an unknown client than a wrong password is an enumeration
  oracle for your customer list.

None of those fail a unit test. All three are addressed here explicitly, and the
reasoning is in the code.

## What's implemented

| Capability | Status |
|---|---|
| MCP Streamable HTTP transport (POST/GET/DELETE, SSE, sessions) | official `@modelcontextprotocol/sdk` |
| OAuth 2.1 `client_credentials` grant | yes |
| `private_key_jwt` client auth (RFC 7523) | yes |
| `client_secret_basic` / `client_secret_post` client auth | yes, constant-time |
| Client secrets stored as scrypt hashes | yes |
| Client ID Metadata Documents + SSRF hardening | yes |
| RFC 8707 resource indicators (audience-bound tokens) | yes |
| RFC 9728 protected resource metadata | yes |
| Client assertion replay prevention (`jti`) | yes, in-memory |
| Scope narrowing at the authorization server | yes |
| Session ownership binding | yes |
| Interactive demo with tamper scenarios | yes |
| `authorization_code` / PKCE / refresh tokens | no — returns 501 |
| Token persistence, revocation, distributed state | no |

---

## Quick start

**Requires Node 22+.** No database, no Docker, no accounts.

```bash
git clone https://github.com/CoreframeLabs/mcp-auth-template.git
cd mcp-auth-template
npm install
cp .env.example .env
```

Set `CIMD_ALLOW_INSECURE=true` in `.env`. Client IDs are HTTPS URLs in
production and the SSRF guard refuses loopback `http://` addresses — which is
exactly what a local demo client is. This flag is why local development works,
and why it defaults to `false`.

### Option A — the interactive demo (start here)

```bash
npm run dev:demo        # http://localhost:3000
```

Open it and click through the scenarios. Each one runs the **real** flow against
the server and shows you the actual HTTP exchange:

| Scenario | Outcome |
|---|---|
| Valid client, correct everything | token issued, tools callable |
| Assertion signed with an unpublished key | 401 at the token endpoint |
| Assertion addressed to a different token endpoint | 401 at the token endpoint |
| Expired assertion | 401 at the token endpoint |
| The same assertion presented twice | second exchange rejected |
| Valid token missing `mcp:tools` | 403 at the MCP server |
| Token with an edited payload | 401 at the MCP server |
| No `Authorization` header | 401 + `WWW-Authenticate` |

### Option B — the two servers separately

```bash
npm run dev:as          # mock authorization server on :4000
npm run dev             # MCP resource server on :3000
npm run demo            # scripted client, prints every step
```

Confirm the boundary is closed:

```bash
curl -i -X POST http://localhost:3000/mcp \
  -H 'content-type: application/json' \
  -H 'accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

You get a `401` whose `WWW-Authenticate` header names the metadata document.
That is not a failure — it is how a compliant MCP client discovers where to get
a token.

> You cannot complete the full flow with `curl` alone: a client must *publish* a
> metadata document at its own `client_id` URL for the authorization server to
> fetch. `npm run demo` stands one up for you.

### Verify everything

```bash
npm test            # 132 tests
npm run typecheck
npm run build
```

---

## Constant-time credential verification

The template compares secrets in constant time **where a secret is actually
being compared**, and documents where it deliberately does not. Both halves
matter — blanket application is cargo cult and hides where the real boundary is.

### Where it is used

**`src/auth/client-secret.ts` — OAuth client secrets.** The primary path.

```ts
const candidate = await scrypt(presented, parsed.salt, parsed.key.length, params);
return timingSafeEqual(candidate, parsed.key);
```

Two independent properties:

1. **Secrets are never stored recoverably.** `CLIENT_SECRETS` holds salted scrypt
   derivations. A leaked config yields no working credential.
2. **Comparison is constant-time.** It runs over fixed-width derived keys, so
   secrets of *differing lengths* compare safely — `crypto.timingSafeEqual`
   throws on length mismatch, and the obvious guard
   (`if (a.length !== b.length) return false`) leaks the secret's length.

**Unknown clients are verified against a decoy hash**, so "no such client" costs
the same as "wrong secret". Without that, the endpoint enumerates your client
list by latency alone. There is a test asserting both responses are byte-identical.

**`src/util/safe-compare.ts`** covers the dev/CI static-token mode, HMAC-ing both
sides under a per-process random key before comparing.

### Where it is deliberately *not* used

- **JWT signature verification.** `jose` already does this correctly.
  Reimplementing it here would be a downgrade, not an improvement.
- **Issuer, audience, scope, `client_id`.** None are secrets. A timing oracle on
  a value the attacker already supplied reveals nothing.

What does more work than constant-time comparison in this codebase is **uniform
failure responses**: expired, wrong-audience and bad-signature all collapse to
one `invalid_token` message, so probing yields no signal. A test asserts the
responses are byte-identical.

### Registering a client secret

```bash
npm run hash-secret -- https://client.example/id
```

Prints the secret once (give it to the client) and the hash (put it in
`CLIENT_SECRETS`). The server refuses to start if it finds a plaintext value.

---

## Client ID Metadata Documents

Instead of pre-registering clients, a `client_id` **is** an HTTPS URL serving a
document describing the client:

```json
{
  "client_id": "https://client.example/mcp-client.json",
  "client_name": "Example Client",
  "token_endpoint_auth_method": "private_key_jwt",
  "grant_types": ["client_credentials"],
  "scope": "mcp:tools",
  "jwks": { "keys": [{ "kty": "EC", "crv": "P-256", "x": "…", "y": "…" }] }
}
```

**This makes the authorization server an HTTP client pointed at an
attacker-supplied URL — a textbook SSRF sink.** `src/auth/cimd.ts` enforces:

- HTTPS only (relaxed solely for loopback dev via `CIMD_ALLOW_INSECURE`)
- no fragment, no embedded credentials in the URL
- DNS resolution checked against loopback, RFC 1918, link-local (including the
  `169.254.169.254` cloud metadata address), CGNAT, multicast, IPv6 equivalents
- redirects **refused outright** rather than re-validated per hop
- `application/json` required; 64 KiB streamed cap; 5s timeout
- `document.client_id` must equal the URL it was fetched from — otherwise any
  host could vouch for another host's identity
- TTL cache over **successes and failures**; negative caching stops a hostile
  `client_id` becoming a traffic amplifier
- an optional **allowlist**, which any publicly reachable deployment must set —
  open resolution means anyone can make your server fetch a URL and report
  whether it worked

### Known limitation: DNS rebinding

The guard resolves the hostname, then `fetch` resolves it again. An entry that
changes between those lookups defeats it. Closing this needs IP pinning with a
custom agent, or an egress allowlist proxy. **Not implemented here** — documented
rather than hidden.

---

## Session security

Streamable HTTP sessions are identified by an `Mcp-Session-Id` header, which is
effectively a bearer credential for an already-authenticated stream. Each session
records the client that opened it; presenting someone else's session id returns
`404` — identical to a nonexistent session, so the status code cannot enumerate
live sessions.

---

## Configuration

Environment-driven, validated by Zod at boot (`src/config.ts`). Invalid config
fails immediately and prints every problem at once, naming the offending
**variables** but never their values — those are exactly where secrets live.

See `.env.example` for every option. There are no credentials in this repository;
the mock AS generates an ephemeral ES256 keypair per boot.

---

## Deploying

### The demo (Railway / Render)

`src/demo/index.ts` serves the AS, the MCP server and the demo UI on one origin.

```bash
docker build -t mcp-auth-demo .
docker run -p 3000:3000 -e PUBLIC_URL=https://your-domain mcp-auth-demo
```

Railway: point it at this repo (`railway.json` is included), set `PUBLIC_URL` to
the public origin, then add a CNAME for your subdomain. Render: use the included
`render.yaml`.

**`PUBLIC_URL` must be the externally reachable origin.** It becomes the OAuth
issuer, the RFC 8707 resource identifier, and the `client_id` URLs the AS
dereferences. Wrong value → every token fails its audience check. The server
refuses to start on a non-HTTPS `PUBLIC_URL` outside loopback.

**Single instance only.** Sessions and the `jti` replay guard are per-process;
a second replica splits them and produces intermittent failures.

### Vercel: not without changes

| Blocker | Effect |
|---|---|
| Sessions in an in-memory `Map` | invocations do not share memory; follow-up requests 404 |
| SSE streams held open | functions have a hard max duration |
| Mock AS mints an ephemeral keypair per boot | each cold start publishes different JWKS; tokens fail *intermittently* |
| `jti` replay guard per-process | replay protection silently stops working |

Stateless mode (`sessionIdGenerator: undefined`) plus a real authorization
server would work. For the full stateful behaviour, use a container host.

---

## Security posture

- CI runs typecheck, tests, build, `npm audit`, **gitleaks** secret scanning and
  **CodeQL** (`security-extended`) on every push and weekly.
- No credentials in the repository; `.env` is gitignored, `.env.example` is not.
- `CLAUDE.md` documents the conventions that keep this true.

### The mock authorization server is a mock

In-memory state, ephemeral keys, no persistence, no revocation, no rate limiting
on the standalone entrypoint. It exists so the flow runs locally. **Do not deploy
it as a real authorization server.** For production, point `MCP_ISSUER_URL` and
`MCP_JWKS_URI` at a real one; the resource server does not care who issued the
token as long as it verifies.

### Dependency advisory

`npm audit` reports a moderate advisory (GHSA-frvp-7c67-39w9) against
`@hono/node-server`, transitively via `@modelcontextprotocol/sdk`: a path
traversal in `serve-static` on **Windows**. This project serves no static files
through Hono, so the path is unreachable. `npm audit fix --force` would downgrade
the SDK to 1.24.3, judged the worse trade. CI fails on high/critical only.
Revisit when the SDK bumps its dependency.

---

## Project layout

```
src/
  app.ts                     MCP resource server (Express)
  config.ts                  Zod-validated environment config
  auth/
    cimd.ts                  CIMD resolution + SSRF hardening
    client-authentication.ts parsing of RFC 6749 client auth
    client-secret.ts         scrypt hashing + constant-time verification
    verifiers.ts             access token verification (JWT + static)
  mcp/server.ts              tool definitions
  mock-as/
    app.ts                   authorization server
    verify-client.ts         proves client identity per mechanism
  demo/                      hosted interactive demo
  util/safe-compare.ts       constant-time string comparison
test/                        132 tests
scripts/
  demo-client.ts             scripted end-to-end client
  hash-secret.ts             client secret generation
```

---

## Licence

MIT. Use it, fork it, ship it.
