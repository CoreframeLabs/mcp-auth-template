# Repository conventions

Guidance for AI agents and humans working in this repository. These are rules
that have already caused bugs when broken, not stylistic preferences.

## Security

**Constant-time comparison is targeted, not blanket.** It is for comparing a
genuine secret against attacker-controlled input. That is:

- `src/auth/client-secret.ts` — OAuth client secrets, compared as scrypt-derived
  keys via `crypto.timingSafeEqual`. This is the primary path.
- `src/util/safe-compare.ts` — `timingSafeEqualString`, used by
  `StaticTokenVerifier` for the dev/CI shared-secret mode.

Secrets are additionally never stored recoverably: `CLIENT_SECRETS` holds scrypt
hashes, never secrets. Hashing and constant-time comparison are independent
requirements — hashing alone still leaks through a naive `===` on the digest,
and constant-time comparison alone still loses the secret to a config dump.

An unregistered client is verified against a decoy hash so it costs the same as
a real one. Without that, the token endpoint is an oracle for which `client_id`s
are registered.

Do **not** extend it to:

- JWT signature verification — `jose` already does this correctly. Wrapping it is
  a downgrade.
- Issuer, audience, scope or `client_id` comparisons — none are secrets. A timing
  oracle on a value the attacker already knows reveals nothing.

Applying it everywhere is cargo cult and obscures where the real boundary is. If
you add a new secret comparison, use it there and say why in a comment.

**Never early-return on length when comparing secrets.** `if (a.length !== b.length)`
leaks the secret's length, and `crypto.timingSafeEqual` throws on mismatched
lengths. HMAC both sides first — that is what `safe-compare.ts` does.

**Failure responses must be uniform.** Expired, wrong-audience and bad-signature
all collapse to one `invalid_token` message. There is a test asserting the
responses are byte-identical. Do not add a helpful error that distinguishes them.

**Never log secrets.** Not tokens, not assertions, not API keys, not config
values. Config validation errors name the offending variable, never its value.

**CIMD resolution is an SSRF sink.** `src/auth/cimd.ts` dereferences
attacker-supplied URLs. Every guard there is load-bearing: https-only, no
redirects, private/link-local/CGNAT blocking, size cap, timeout, content-type
check, exact `client_id`/URL match, negative caching. Any publicly reachable
deployment must also set an `allowlist`. Do not relax these for convenience.

`CIMD_ALLOW_INSECURE=true` disables the SSRF guard. It exists for loopback
development only and must never be set on a deployed origin.

## Testing

**Run the tests. Report real numbers.** Do not describe behaviour you have not
observed. Two live bugs in this repo were found only by running the suite, not by
reading the code.

**No mocks where the wire behaviour is the point.** CIMD tests use real sockets
and real key material, because the security properties live in content-type,
size and redirect handling that a fetch mock would let regress silently.

**A test that passes for the wrong reason is a defect.** If an assertion cannot
fail — because HTTP normalises the input, or the code under test was mocked away
— move it to where it is meaningful or delete it. Do not keep it for the count.

## Style

- TypeScript strict, `noUncheckedIndexedAccess` on. No `any`, no non-null
  assertions outside tests unless the invariant is stated in a comment.
- 4-space indent, single quotes, semicolons.
- Comments explain *why*, never *what*. If a line needs a comment to say what it
  does, rewrite the line.
- Config is environment-driven and validated by Zod at boot. Fail loudly and list
  every problem at once.

## Things that will bite you

- `requireBearerAuth` rejects any `AuthInfo` without a numeric `expiresAt`. A
  verifier that omits it will 401 tokens that are perfectly valid.
- The SDK refuses a non-HTTPS issuer except on localhost, which is why OAuth
  discovery metadata is only mounted in `jwt` mode.
- Sessions and the `jti` replay guard are per-process. Any multi-instance deploy
  needs a shared store first, or you get intermittent, hard-to-diagnose failures.
