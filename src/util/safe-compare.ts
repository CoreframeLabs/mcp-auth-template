import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

/**
 * Per-process blinding key. Regenerated on every boot, never persisted, never
 * logged. Its only job is to make the digests below unpredictable to an attacker
 * who is measuring our response times.
 */
const BLINDING_KEY = randomBytes(32);

/**
 * Constant-time string equality.
 *
 * `crypto.timingSafeEqual` throws when the two buffers differ in length, and the
 * obvious guard — an early `if (a.length !== b.length) return false` — leaks the
 * secret's length through timing. HMAC-ing both sides first produces two
 * fixed-width 32-byte digests, so the comparison is constant-time *and*
 * length-agnostic.
 *
 * Use this for any secret-bearing value: shared tokens, client secrets, webhook
 * signatures, password reset nonces.
 *
 * Do NOT reach for it when verifying a JWT signature — `jose` already performs
 * that comparison correctly, and hand-rolling it here would be a downgrade. See
 * README "Where constant-time comparison actually matters".
 */
export function timingSafeEqualString(a: string, b: string): boolean {
    const da = createHmac('sha256', BLINDING_KEY).update(a, 'utf8').digest();
    const db = createHmac('sha256', BLINDING_KEY).update(b, 'utf8').digest();
    return timingSafeEqual(da, db);
}
