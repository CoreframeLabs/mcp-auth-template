import { randomBytes, scrypt as scryptCb, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';

const scrypt = promisify(scryptCb) as (
    password: string | Buffer,
    salt: Buffer,
    keylen: number,
    options: { N: number; r: number; p: number; maxmem: number },
) => Promise<Buffer>;

/**
 * Client secret storage and verification.
 *
 * Two properties matter here, and they are independent:
 *
 *   1. Secrets are never stored in recoverable form. A leaked configuration file
 *      or database dump must not hand over working credentials, so what is
 *      persisted is a salted scrypt derivation, not the secret.
 *
 *   2. Verification is constant-time with respect to the secret. The comparison
 *      is over fixed-width derived keys via crypto.timingSafeEqual, so an
 *      attacker measuring response latency learns nothing about how much of
 *      their guess was correct.
 *
 * Both are required. Hashing alone still leaks through a naive `===` on the
 * digest; constant-time comparison alone still loses the secret to a dump.
 */

/** scrypt parameters. N is the cost; raising it slows every verification. */
const PARAMS = { N: 16_384, r: 8, p: 1 } as const;
const KEY_LENGTH = 32;
const SALT_LENGTH = 16;
/** scrypt needs roughly 128 * N * r bytes; give it headroom or it throws. */
const MAX_MEM = 64 * 1024 * 1024;

const PREFIX = 'scrypt';

/** Minimum length we will accept when hashing a new secret. */
export const MIN_SECRET_LENGTH = 32;

export class WeakSecretError extends Error {
    constructor(length: number) {
        super(
            `client secret must be at least ${MIN_SECRET_LENGTH} characters (got ${length}). ` +
                'Generate one with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'base64url\'))"',
        );
        this.name = 'WeakSecretError';
    }
}

async function derive(secret: string, salt: Buffer): Promise<Buffer> {
    return scrypt(secret, salt, KEY_LENGTH, { ...PARAMS, maxmem: MAX_MEM });
}

/**
 * Hashes a client secret for storage.
 *
 * Returns `scrypt$N$r$p$<salt-b64url>$<key-b64url>` — self-describing, so the
 * cost parameters can be raised later without invalidating existing records.
 */
export async function hashClientSecret(secret: string): Promise<string> {
    if (secret.length < MIN_SECRET_LENGTH) throw new WeakSecretError(secret.length);
    const salt = randomBytes(SALT_LENGTH);
    const key = await derive(secret, salt);
    return [PREFIX, PARAMS.N, PARAMS.r, PARAMS.p, salt.toString('base64url'), key.toString('base64url')].join('$');
}

interface ParsedHash {
    N: number;
    r: number;
    p: number;
    salt: Buffer;
    key: Buffer;
}

function parseHash(stored: string): ParsedHash | null {
    const parts = stored.split('$');
    if (parts.length !== 6 || parts[0] !== PREFIX) return null;
    const [, n, r, p, salt, key] = parts;
    const parsed = {
        N: Number(n),
        r: Number(r),
        p: Number(p),
        salt: Buffer.from(salt!, 'base64url'),
        key: Buffer.from(key!, 'base64url'),
    };
    if (!Number.isInteger(parsed.N) || !Number.isInteger(parsed.r) || !Number.isInteger(parsed.p)) return null;
    if (parsed.salt.length === 0 || parsed.key.length === 0) return null;
    return parsed;
}

/**
 * Verifies a presented secret against a stored hash, in constant time with
 * respect to the secret.
 *
 * Note the comparison is over the *derived keys*, which are always KEY_LENGTH
 * bytes. That is what makes it safe for secrets of differing lengths:
 * timingSafeEqual throws when its inputs differ in length, and guarding that
 * with an early length check would leak the secret's length through timing.
 */
export async function verifyClientSecret(presented: string, stored: string): Promise<boolean> {
    const parsed = parseHash(stored);
    if (!parsed) return false;
    const candidate = await scrypt(presented, parsed.salt, parsed.key.length, {
        N: parsed.N,
        r: parsed.r,
        p: parsed.p,
        maxmem: MAX_MEM,
    });
    return timingSafeEqual(candidate, parsed.key);
}

/**
 * A stored hash for a client that does not exist.
 *
 * Verifying an unknown client against this costs the same as verifying a real
 * one, so "no such client" and "wrong secret" take the same time. Without it,
 * the token endpoint becomes an oracle for which client_ids are registered:
 * unknown clients would return immediately while real ones pay for a scrypt
 * derivation, a difference of milliseconds that is trivially measurable.
 */
let decoyHash: string | null = null;

async function getDecoy(): Promise<string> {
    decoyHash ??= await hashClientSecret(randomBytes(32).toString('base64url'));
    return decoyHash;
}

export interface ClientSecretRecord {
    clientId: string;
    /** scrypt hash, never the secret itself. */
    hash: string;
}

/**
 * Constant-time-ish lookup and verification of client secrets.
 *
 * Deliberately does not expose "is this client registered?" as a separate
 * question — every path performs one derivation and returns a boolean.
 */
export class ClientSecretStore {
    private readonly records = new Map<string, string>();

    constructor(records: ClientSecretRecord[] = []) {
        for (const record of records) this.records.set(record.clientId, record.hash);
    }

    get size(): number {
        return this.records.size;
    }

    has(clientId: string): boolean {
        return this.records.has(clientId);
    }

    /**
     * True only when the client is registered AND the secret matches.
     *
     * An unregistered client is verified against a decoy so the work performed
     * is indistinguishable from a failed match on a real client.
     */
    async verify(clientId: string, presentedSecret: string): Promise<boolean> {
        const stored = this.records.get(clientId);
        if (stored === undefined) {
            await verifyClientSecret(presentedSecret, await getDecoy());
            return false;
        }
        return verifyClientSecret(presentedSecret, stored);
    }
}

/**
 * Builds a store from `CLIENT_SECRETS`, a JSON object of
 * `{ "<client_id>": "<scrypt hash>" }`.
 *
 * Hashes only. Accepting a plaintext secret here would put a live credential in
 * the process environment, where it reaches crash dumps, `docker inspect`, and
 * any logger that prints env on startup. Generate hashes with
 * `npm run hash-secret`.
 */
export function loadClientSecretStore(raw: string | undefined): ClientSecretStore {
    if (!raw || raw.trim() === '') return new ClientSecretStore();

    let parsed: unknown;
    try {
        parsed = JSON.parse(raw);
    } catch {
        throw new Error('CLIENT_SECRETS must be valid JSON of { "<client_id>": "<scrypt hash>" }');
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
        throw new Error('CLIENT_SECRETS must be a JSON object mapping client_id to a scrypt hash');
    }

    const records: ClientSecretRecord[] = [];
    for (const [clientId, value] of Object.entries(parsed as Record<string, unknown>)) {
        if (typeof value !== 'string' || !value.startsWith(`${PREFIX}$`)) {
            // Names the offending client_id but never the value, since a
            // misconfiguration here is most likely a plaintext secret.
            throw new Error(
                `CLIENT_SECRETS entry for "${clientId}" is not a scrypt hash. ` +
                    'Store hashes, not secrets. Generate one with: npm run hash-secret',
            );
        }
        records.push({ clientId, hash: value });
    }
    return new ClientSecretStore(records);
}
