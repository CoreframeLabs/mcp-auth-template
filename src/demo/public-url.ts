/**
 * Resolving the demo's public origin from the environment.
 *
 * This is the single most error-prone piece of deploying the demo: the public
 * URL becomes the OAuth issuer, the RFC 8707 resource identifier and the
 * client_id URLs, so a wrong value breaks every token's audience check. And the
 * failure is especially nasty on a platform that rolls back to the previous
 * deployment when the new one exits — the misconfigured deploy dies, the old
 * (also-wrong) one keeps serving, and it looks like the variable was ignored.
 *
 * So this module is deliberately forgiving of the mistakes people actually make,
 * and pure/testable rather than inlined in the entrypoint.
 */

export class PublicUrlError extends Error {
    constructor(
        readonly raw: string,
        readonly source: string,
        reason: string,
    ) {
        super(`Cannot use ${source}="${raw}" as the public URL: ${reason}`);
        this.name = 'PublicUrlError';
    }
}

const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '::1']);

/** Trims whitespace and a single pair of surrounding quotes. */
function clean(value: string | undefined): string | undefined {
    if (value == null) return undefined;
    const trimmed = value.trim().replace(/^["']|["']$/g, '').trim();
    return trimmed.length > 0 ? trimmed : undefined;
}

/**
 * Parses a value into an http(s) URL, prepending https:// when no usable scheme
 * is present.
 *
 * The retry is what saves the most common deploy mistake — pasting a bare
 * `foo.up.railway.app`. It also correctly handles `localhost:8080`, which parses
 * on the first pass as scheme `localhost:` (not http/https) and so falls through
 * to the https:// retry.
 */
function toHttpUrl(raw: string): URL | null {
    for (const candidate of [raw, `https://${raw}`]) {
        try {
            const url = new URL(candidate);
            if (url.protocol === 'http:' || url.protocol === 'https:') return url;
        } catch {
            // try the next candidate
        }
    }
    return null;
}

export interface ResolvedPublicUrl {
    /** Normalised origin, no trailing slash. */
    url: string;
    /** Which environment variable it came from — surfaced in boot logs. */
    source: string;
    isLoopback: boolean;
    /** True when we fell back to localhost despite signs of a real deployment. */
    suspectedMisconfiguration: boolean;
}

interface Candidate {
    raw: string;
    source: string;
}

/**
 * Picks the public URL from, in order: an explicit PUBLIC_URL, Railway's
 * injected domain, Render's injected URL, then a localhost default.
 *
 * Auto-detecting the platform variables means a from-scratch Railway or Render
 * deploy needs no manual PUBLIC_URL at all, once a domain has been generated.
 */
function pickCandidate(env: NodeJS.ProcessEnv, port: number): Candidate {
    const explicit = clean(env['PUBLIC_URL']);
    if (explicit) return { raw: explicit, source: 'PUBLIC_URL' };

    // Railway injects the bare domain (no scheme) once a public domain exists.
    const railway = clean(env['RAILWAY_PUBLIC_DOMAIN']);
    if (railway) return { raw: railway, source: 'RAILWAY_PUBLIC_DOMAIN' };

    // Render injects a full URL including scheme.
    const render = clean(env['RENDER_EXTERNAL_URL']);
    if (render) return { raw: render, source: 'RENDER_EXTERNAL_URL' };

    return { raw: `http://localhost:${port}`, source: 'default' };
}

/** Signs that we are on a real host, used to detect a localhost fallback there. */
function looksDeployed(env: NodeJS.ProcessEnv): boolean {
    return Boolean(
        env['RAILWAY_ENVIRONMENT'] ??
            env['RAILWAY_PROJECT_ID'] ??
            env['RENDER'] ??
            env['RENDER_SERVICE_ID'] ??
            (env['NODE_ENV'] === 'production' ? '1' : undefined),
    );
}

export function resolvePublicUrl(env: NodeJS.ProcessEnv, port: number): ResolvedPublicUrl {
    const { raw, source } = pickCandidate(env, port);

    const url = toHttpUrl(raw);
    if (!url) {
        throw new PublicUrlError(raw, source, 'not a valid http(s) URL or hostname');
    }

    const isLoopback = LOOPBACK_HOSTS.has(url.hostname);
    if (url.protocol === 'http:' && !isLoopback) {
        // A schemeless value would already have been upgraded to https, so an
        // http origin on a public host is an explicit, and wrong, choice.
        throw new PublicUrlError(raw, source, 'a public origin must use https, not http');
    }

    // Origin only — strip any path/query/hash and the trailing slash so the
    // canonical resource identifier is stable.
    const normalized = `${url.protocol}//${url.host}`;

    return {
        url: normalized,
        source,
        isLoopback,
        suspectedMisconfiguration: source === 'default' && looksDeployed(env),
    };
}
