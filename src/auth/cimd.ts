import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { z } from 'zod';

/**
 * Client ID Metadata Documents.
 *
 * Instead of pre-registering every client, a client's `client_id` *is* an https
 * URL that dereferences to a JSON document describing it. The authorization
 * server fetches that document to learn how to authenticate the client — here,
 * which public keys sign its `private_key_jwt` client assertions.
 *
 * That makes the AS an HTTP client acting on an attacker-supplied URL, which is
 * a textbook SSRF sink. Everything defensive in this file exists for that reason.
 */

const MAX_DOCUMENT_BYTES = 64 * 1024;
const FETCH_TIMEOUT_MS = 5_000;

const JwkSchema = z.looseObject({ kty: z.string().min(1) });

export const ClientMetadataSchema = z.object({
    client_id: z.string().min(1),
    client_name: z.string().max(200).optional(),
    jwks_uri: z.string().optional(),
    jwks: z.object({ keys: z.array(JwkSchema).min(1) }).optional(),
    grant_types: z.array(z.string()).default(['client_credentials']),
    token_endpoint_auth_method: z.string().default('private_key_jwt'),
    scope: z.string().optional(),
    redirect_uris: z.array(z.string()).optional(),
});

export type ClientMetadata = z.infer<typeof ClientMetadataSchema>;

export class CimdError extends Error {
    constructor(
        message: string,
        readonly clientId: string,
    ) {
        super(message);
        this.name = 'CimdError';
    }
}

/**
 * Ranges that must never be reachable from a user-supplied client_id. Covers
 * loopback, RFC 1918, link-local (including the 169.254.169.254 cloud metadata
 * endpoint), CGNAT, and the IPv6 equivalents.
 */
function isPrivateAddress(addr: string): boolean {
    const family = isIP(addr);
    if (family === 4) {
        const parts = addr.split('.').map(Number);
        const [a = 0, b = 0] = parts;
        if (a === 10 || a === 127 || a === 0) return true;
        if (a === 172 && b >= 16 && b <= 31) return true;
        if (a === 192 && b === 168) return true;
        if (a === 169 && b === 254) return true;
        if (a === 100 && b >= 64 && b <= 127) return true;
        if (a >= 224) return true;
        return false;
    }
    if (family === 6) {
        const v6 = addr.toLowerCase().replace(/^\[|\]$/g, '');
        if (v6 === '::1' || v6 === '::') return true;
        if (v6.startsWith('fe80') || v6.startsWith('fc') || v6.startsWith('fd')) return true;
        // IPv4-mapped (::ffff:10.0.0.1) — re-check the embedded v4 address.
        const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(v6);
        if (mapped?.[1]) return isPrivateAddress(mapped[1]);
        return false;
    }
    return false;
}

export interface CimdOptions {
    /**
     * Local development only. Permits http:// and loopback/private client_id
     * URLs, which disables the SSRF guard entirely.
     */
    allowInsecure: boolean;
    cacheTtlSeconds: number;
    /** Injectable for tests. Defaults to global fetch. */
    fetchImpl?: typeof fetch;
}

async function assertFetchableUrl(url: URL, label: string, clientId: string, allowInsecure: boolean): Promise<void> {
    if (url.protocol !== 'https:' && !(allowInsecure && url.protocol === 'http:')) {
        throw new CimdError(`${label} must use https`, clientId);
    }
    if (url.hash) throw new CimdError(`${label} must not contain a fragment`, clientId);
    if (url.username || url.password) {
        throw new CimdError(`${label} must not contain credentials`, clientId);
    }
    if (allowInsecure) return;

    const host = url.hostname.replace(/^\[|\]$/g, '');
    const addresses = isIP(host) ? [host] : (await lookup(host, { all: true })).map((r) => r.address);
    if (addresses.length === 0) throw new CimdError(`${label} does not resolve`, clientId);
    for (const addr of addresses) {
        if (isPrivateAddress(addr)) {
            throw new CimdError(`${label} resolves to a non-public address`, clientId);
        }
    }
}

/** Reads a response body, aborting if it exceeds the cap. */
async function readCapped(res: Response, clientId: string): Promise<string> {
    const declared = Number(res.headers.get('content-length') ?? '0');
    if (declared > MAX_DOCUMENT_BYTES) {
        throw new CimdError('client metadata document is too large', clientId);
    }
    const reader = res.body?.getReader();
    if (!reader) throw new CimdError('client metadata document has no body', clientId);

    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > MAX_DOCUMENT_BYTES) {
            await reader.cancel();
            throw new CimdError('client metadata document is too large', clientId);
        }
        chunks.push(value);
    }
    return Buffer.concat(chunks.map((c) => Buffer.from(c))).toString('utf8');
}

interface CacheEntry {
    expiresAt: number;
    result: { ok: true; doc: ClientMetadata } | { ok: false; message: string };
}

/**
 * Resolves and validates Client ID Metadata Documents, with a TTL cache over
 * both successes and failures. Negative caching matters: without it, a client_id
 * pointing at a slow or hostile host is a free amplification vector.
 */
export class CimdResolver {
    private readonly cache = new Map<string, CacheEntry>();
    private readonly fetchImpl: typeof fetch;

    constructor(private readonly options: CimdOptions) {
        this.fetchImpl = options.fetchImpl ?? globalThis.fetch;
    }

    clearCache(): void {
        this.cache.clear();
    }

    async resolve(clientId: string): Promise<ClientMetadata> {
        const cached = this.cache.get(clientId);
        if (cached && cached.expiresAt > Date.now()) {
            if (cached.result.ok) return cached.result.doc;
            throw new CimdError(cached.result.message, clientId);
        }

        try {
            const doc = await this.fetchAndValidate(clientId);
            this.cache.set(clientId, {
                expiresAt: Date.now() + this.options.cacheTtlSeconds * 1000,
                result: { ok: true, doc },
            });
            return doc;
        } catch (err) {
            const message = err instanceof CimdError ? err.message : 'client metadata document could not be retrieved';
            this.cache.set(clientId, {
                expiresAt: Date.now() + Math.min(this.options.cacheTtlSeconds, 60) * 1000,
                result: { ok: false, message },
            });
            throw err instanceof CimdError ? err : new CimdError(message, clientId);
        }
    }

    private async fetchAndValidate(clientId: string): Promise<ClientMetadata> {
        let url: URL;
        try {
            url = new URL(clientId);
        } catch {
            throw new CimdError('client_id must be an absolute URL', clientId);
        }

        await assertFetchableUrl(url, 'client_id', clientId, this.options.allowInsecure);

        let res: Response;
        try {
            res = await this.fetchImpl(url, {
                // A redirect could bounce us past the SSRF checks above, so refuse
                // to follow them rather than re-validating each hop.
                redirect: 'error',
                signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
                headers: { accept: 'application/json' },
            });
        } catch {
            throw new CimdError('client metadata document could not be fetched', clientId);
        }

        if (!res.ok) {
            throw new CimdError(`client metadata document returned HTTP ${res.status}`, clientId);
        }
        const contentType = (res.headers.get('content-type') ?? '').toLowerCase();
        if (!contentType.startsWith('application/json')) {
            throw new CimdError('client metadata document must be application/json', clientId);
        }

        const body = await readCapped(res, clientId);
        let json: unknown;
        try {
            json = JSON.parse(body);
        } catch {
            throw new CimdError('client metadata document is not valid JSON', clientId);
        }

        const parsed = ClientMetadataSchema.safeParse(json);
        if (!parsed.success) {
            throw new CimdError('client metadata document failed schema validation', clientId);
        }
        const doc = parsed.data;

        // The document must claim the exact identity it was fetched from,
        // otherwise any host could vouch for any other host's client_id.
        if (doc.client_id !== clientId) {
            throw new CimdError('client metadata document client_id does not match its URL', clientId);
        }
        if (doc.token_endpoint_auth_method !== 'private_key_jwt') {
            throw new CimdError('only private_key_jwt client authentication is supported', clientId);
        }
        if (!doc.jwks && !doc.jwks_uri) {
            throw new CimdError('client metadata document must supply jwks or jwks_uri', clientId);
        }
        if (doc.jwks && doc.jwks_uri) {
            throw new CimdError('client metadata document must not supply both jwks and jwks_uri', clientId);
        }
        if (doc.jwks_uri) {
            await assertFetchableUrl(new URL(doc.jwks_uri), 'jwks_uri', clientId, this.options.allowInsecure);
        }
        return doc;
    }
}
