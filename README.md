# mcp-auth-template

A remote **Model Context Protocol** server over Streamable HTTP, behind a real
OAuth 2.1 resource-server boundary, with clients identified by **Client ID
Metadata Documents (CIMD)** instead of pre-registration.

It ships with a mock authorization server so the whole flow runs on one machine
with no external dependencies.

```
┌────────────┐  1. POST /token (private_key_jwt + resource)   ┌──────────────────────┐
│ MCP client │ ─────────────────────────────────────────────▶ │ authorization server │
│            │                                               │  (mock, in-repo)     │
│  client_id │ ◀───────────── 2. access token (aud = RS) ──── │                      │
│  = an https│                                               └──────────┬───────────┘
│    URL     │                                                    3. fetch CIMD
│            │                                                          │
│            │                                                          ▼
│            │                                              ┌──────────────────────┐
│            │  4. POST /mcp  Authorization: Bearer …       │ client's own host    │
│            │ ───────────────────────────────────────────▶ │ serving its metadata │
└────────────┘                                              └──────────────────────┘
                            │
                            ▼
                 ┌──────────────────────┐
                 │ MCP resource server  │  verifies iss + aud + scope + signature
                 │ Streamable HTTP /mcp │  via the AS's JWKS
                 └──────────────────────┘
```

## Quick start

Requires **Node 22+**. No database, no Docker, no external accounts.

```bash
npm install
cp .env.example .env
```

Then set `CIMD_ALLOW_INSECURE=true` in `.env`. Client IDs are HTTPS URLs in
production, and the SSRF guard refuses loopback `http://` addresses — which is
exactly what a local demo client is. This flag is what makes local development
possible, and it is why the default is `false`.

Two terminals:

```bash
npm run dev:as     # terminal 1 — mock authorization server on :4000
npm run dev        # terminal 2 — MCP resource server on :3000
```

Confirm the boundary is closed:

```bash
curl -i -X POST http://localhost:3000/mcp \
  -H 'content-type: application/json' \
  -H 'accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
# → 401 with:
#   WWW-Authenticate: Bearer error="invalid_token", …,
#     resource_metadata="http://localhost:3000/.well-known/oauth-protected-resource/mcp"
```

That 401 is the whole point: it tells a compliant MCP client exactly where to go
to get a token.

Then walk the full flow, in a third terminal:

```bash
npm run demo
```

`scripts/demo-client.ts` publishes a Client ID Metadata Document, signs a
`private_key_jwt` assertion with the matching key, exchanges it for a
resource-scoped access token, calls `tools/list`, `whoami` and `echo` over
Streamable HTTP, and finally proves an invalid token is rejected — printing each
step. It is the fastest way to see what the server actually does.

You cannot reproduce this with `curl` alone: the client must *publish* a metadata
document at its own `client_id` URL for the authorization server to fetch, which
needs a running HTTP server. That is what the demo script provides.

## What is actually implemented

| Piece | Status |
|---|---|
| Streamable HTTP transport (POST/GET/DELETE, SSE, sessions) | via official `@modelcontextprotocol/sdk` |
| RFC 9728 protected resource metadata | yes |
| RFC 8707 resource indicators (audience-bound tokens) | yes |
| `client_credentials` grant | yes |
| `private_key_jwt` client authentication (RFC 7523) | yes |
| CIMD client identity + SSRF hardening | yes |
| Client assertion replay prevention (`jti`) | yes, in-memory |
| Scope narrowing at the AS | yes |
| Session ownership binding | yes |
| `authorization_code` / PKCE / refresh tokens | **no** — returns 501 |
| Token persistence, revocation, rate limiting | **no** |

## Client ID Metadata Documents

Rather than registering every client ahead of time, a client's `client_id` *is*
an `https` URL that serves a JSON document describing it:

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

The authorization server dereferences that URL to learn which keys may sign the
client's assertions. **This makes the AS an HTTP client pointed at an
attacker-supplied URL**, which is a textbook SSRF sink. `src/auth/cimd.ts`
therefore enforces:

- `https` only (relaxed only when `CIMD_ALLOW_INSECURE=true`, for localhost dev)
- no fragment, no embedded credentials in the URL
- DNS resolution checked against loopback, RFC 1918, link-local
  (incl. `169.254.169.254`), CGNAT, multicast, and the IPv6 equivalents
- redirects refused outright rather than re-validated per hop
- `application/json` content-type required
- 64 KiB body cap, streamed and aborted on overrun
- 5 s timeout
- `document.client_id` must equal the URL it was fetched from — without this,
  any host could vouch for any other host's identity
- TTL cache over **successes and failures**; negative caching is what stops a
  hostile `client_id` becoming a traffic amplifier

### Known limitation: DNS rebinding

The SSRF check resolves the hostname, then `fetch` resolves it again. A DNS
entry that changes between those two lookups defeats the guard. Closing this
properly requires pinning the validated IP and dialing it directly with a
custom agent while preserving SNI/Host. It is **not** implemented here. In
production, route this fetch through an egress proxy with an allowlist.

## Where constant-time comparison actually matters

The brief was "enforce constant-time comparison on token checks." Applied
literally and everywhere, that is cargo cult. Here is the honest breakdown:

**`timingSafeEqualString` is used in exactly one place** —
`StaticTokenVerifier`, which compares a caller-supplied bearer token against a
configured shared secret. That is a real secret compared with a real attacker in
control of one side, so a naive `===` would leak it byte-by-byte through timing.

`src/util/safe-compare.ts` HMACs both sides under a per-process random key before
calling `crypto.timingSafeEqual`. The obvious alternative — an early
`if (a.length !== b.length) return false` — leaks the secret's *length*, and
`timingSafeEqual` throws outright on mismatched lengths.

**It is deliberately NOT used for:**

- *JWT signature verification.* `jose` already performs this correctly. Wrapping
  it would be a downgrade, not an improvement.
- *Issuer, audience, scope, and `client_id` comparisons.* None are secrets. A
  timing oracle on a value the attacker already knows reveals nothing.
- *Session id lookup.* A hash map lookup is not a comparison an attacker can
  usefully time here, and the session is additionally bound to its owner.

Uniform failure responses do more work than constant-time comparison in this
codebase: "expired", "wrong audience" and "bad signature" all collapse to a
single `invalid_token` message, so probing yields no signal. There is a test
asserting exactly that.

## Session security

Streamable HTTP sessions are identified by an `Mcp-Session-Id` header, which is
effectively a bearer credential for an already-authenticated stream. Each
session records the `clientId` that opened it, and a request presenting someone
else's session id gets `404` — the same response as a session that does not
exist, so an attacker cannot use the status code to enumerate live sessions.

## Configuration

All configuration is environment-driven and validated at boot by Zod
(`src/config.ts`). Invalid config fails immediately and prints every problem at
once, naming only the offending **variables** — never their values, since those
are exactly where secrets live.

There are no credentials in this repository. The mock AS generates an ephemeral
ES256 keypair on every boot, so there is no long-lived private key to leak;
restarting it invalidates outstanding tokens, which is correct for a dev server.

## Tests

```bash
npm test          # 66 tests, 5 files
npm run typecheck
npm run build
```

| File | Covers |
|---|---|
| `test/safe-compare.test.ts` | length mismatch without throwing, prefixes, unicode NFC/NFD |
| `test/cimd.test.ts` | document validation, every SSRF guard, caching, negative caching |
| `test/token-endpoint.test.ts` | grant/assertion/audience/replay/scope-narrowing rejection paths |
| `test/resource-server.test.ts` | full MCP handshake, identity reaching tool code, 7 rejection paths, session isolation |
| `test/static-mode.test.ts` | shared-secret accept/reject |

Tests use real sockets and real key material rather than mocks — CIMD's security
properties live in content-type, size and redirect handling on the wire, which a
fetch mock would let regress silently.

Two findings that came out of *running* these rather than writing them:

1. `requireBearerAuth` rejects any `AuthInfo` without a numeric `expiresAt`, so
   valid static tokens were being 401'd. Fixed by reporting a synthetic expiry.
2. A "rejects whitespace-padded token" HTTP test was wrong: RFC 9110 strips
   optional whitespace around header values, so the padding never arrives. The
   assertion was moved down to the verifier, where it is meaningful.

## Deploying

### Vercel: not without changes

Vercel is a poor fit for this server as written, and it is worth being precise
about why rather than discovering it after a deploy.

| Blocker | Why it breaks | What it would take |
|---|---|---|
| Sessions live in an in-memory `Map` | Serverless invocations do not share memory. A session created by one instance is invisible to the next, so every follow-up request 404s. | Run the transport stateless (`sessionIdGenerator: undefined`), or move sessions to Redis. |
| Streamable HTTP holds an SSE stream open | Functions have a hard max duration. Long-lived server→client streams get severed mid-flight. | Stateless request/response only — no server-initiated notifications. |
| The mock AS mints an **ephemeral keypair per boot** | Every cold start publishes a different JWKS, so tokens issued by one instance fail verification on the next, seemingly at random. | Do not deploy the mock AS. Point at a real authorization server, or load a fixed signing key from a secret. |
| The `jti` replay guard is per-process | Assertion replay protection silently stops working across instances. | Shared store (Redis). |

**The honest recommendation:** deploy the resource server *stateless* on Vercel
and point `MCP_ISSUER_URL` / `MCP_JWKS_URI` at a real authorization server. The
mock AS is a development tool and should never be public.

If you want the full stateful behaviour, use a container host that gives you a
long-lived process — Fly.io, Railway, or Render. A `Dockerfile` on any of those
is materially less work than reshaping this for serverless.

Note that Vercel's session, duration and memory constraints are what force the
design change here — the code is not doing anything unusual. Any stateful
long-lived-connection server meets the same wall.

### Neither mode is deployed today

This repository has never been deployed to any environment. Nothing above has
been executed against a real Vercel project; it is an analysis of the code
against documented platform constraints, not a deployment report.

## Do not deploy this as-is

- The mock AS is a **mock**: in-memory state, ephemeral keys, no persistence, no
  rate limiting, no revocation, no admin surface.
- Static auth mode is a single shared secret that never expires.
- The `jti` replay guard and session map are per-process and will not hold across
  multiple instances. Use Redis or equivalent.
- No rate limiting anywhere. Add it at the edge.
- Set `CIMD_ALLOW_INSECURE=false` (the default). `true` disables the SSRF guard.

### Dependency advisory

`npm audit` reports a moderate advisory (GHSA-frvp-7c67-39w9) against
`@hono/node-server`, pulled in transitively by `@modelcontextprotocol/sdk`. It is
a path traversal in `serve-static` on **Windows** via an encoded backslash. This
project serves no static files through Hono, so the vulnerable code path is not
reachable. `npm audit fix --force` would downgrade the SDK to 1.24.3, which was
judged the worse trade. Re-evaluate when the SDK bumps its dependency.

## Licence

MIT.
