import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';
import { InsufficientScopeError, InvalidTokenError } from '@modelcontextprotocol/sdk/server/auth/errors.js';
import type { OAuthTokenVerifier } from '@modelcontextprotocol/sdk/server/auth/provider.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import { timingSafeEqualString } from '../util/safe-compare.js';

export const ACCESS_TOKEN_ALG = 'ES256';

/** Synthetic lifetime reported for static-mode tokens. See StaticTokenVerifier. */
const STATIC_TOKEN_TTL_SECONDS = 3600;

function scopesFrom(payload: JWTPayload): string[] {
    const raw = payload['scope'];
    if (typeof raw === 'string') return raw.split(/\s+/).filter(Boolean);
    if (Array.isArray(raw)) return raw.filter((s): s is string => typeof s === 'string');
    return [];
}

/**
 * Verifies OAuth 2.1 access tokens issued as JWTs by the configured issuer.
 *
 * Note there is no constant-time comparison in here, and that is deliberate:
 * every check below is over a *non-secret* value (issuer, audience, scope), and
 * the one comparison that does involve a secret — the token's signature — is
 * performed inside `jose`, which already does it correctly.
 */
export class JwtAccessTokenVerifier implements OAuthTokenVerifier {
    private readonly jwks: ReturnType<typeof createRemoteJWKSet>;

    constructor(
        private readonly options: {
            issuer: string;
            /** Canonical RFC 8707 resource identifier this server answers to. */
            resource: string;
            jwksUri: string;
            requiredScopes: string[];
            clockToleranceSeconds?: number;
        },
    ) {
        this.jwks = createRemoteJWKSet(new URL(options.jwksUri), {
            cacheMaxAge: 600_000,
            timeoutDuration: 5_000,
        });
    }

    async verifyAccessToken(token: string): Promise<AuthInfo> {
        let payload: JWTPayload;
        try {
            ({ payload } = await jwtVerify(token, this.jwks, {
                issuer: this.options.issuer,
                audience: this.options.resource,
                algorithms: [ACCESS_TOKEN_ALG],
                clockTolerance: this.options.clockToleranceSeconds ?? 5,
                requiredClaims: ['sub', 'exp', 'iat', 'jti'],
            }));
        } catch {
            // Never surface the underlying jose error: it distinguishes "bad
            // signature" from "wrong audience" from "expired", which tells an
            // attacker which half of their guess was right.
            throw new InvalidTokenError('access token is invalid or expired');
        }

        const scopes = scopesFrom(payload);
        const missing = this.options.requiredScopes.filter((s) => !scopes.includes(s));
        if (missing.length > 0) {
            throw new InsufficientScopeError(`access token is missing required scope(s): ${missing.join(', ')}`);
        }

        const authInfo: AuthInfo = {
            token,
            clientId: payload.sub!,
            scopes,
            resource: new URL(this.options.resource),
            extra: { jti: payload.jti },
        };
        if (typeof payload.exp === 'number') authInfo.expiresAt = payload.exp;
        return authInfo;
    }
}

/**
 * Single shared-secret verifier for local development and CI, where standing up
 * a full authorization server per test run is not worth it.
 *
 * This is the one place in the resource server where a genuine secret is
 * compared, so it is the one place `timingSafeEqualString` belongs.
 */
export class StaticTokenVerifier implements OAuthTokenVerifier {
    constructor(
        private readonly options: {
            token: string;
            resource: string;
            scopes: string[];
            clientId?: string;
        },
    ) {
        if (options.token.length < 32) {
            throw new Error('StaticTokenVerifier requires a token of at least 32 characters');
        }
    }

    async verifyAccessToken(token: string): Promise<AuthInfo> {
        if (!timingSafeEqualString(token, this.options.token)) {
            throw new InvalidTokenError('access token is invalid');
        }
        return {
            token,
            clientId: this.options.clientId ?? 'static-dev-client',
            scopes: [...this.options.scopes],
            resource: new URL(this.options.resource),
            // requireBearerAuth rejects any AuthInfo without a numeric expiry, so
            // a static token has to present one. It is synthetic — the secret
            // itself never expires, which is precisely why this mode is not for
            // production.
            expiresAt: Math.floor(Date.now() / 1000) + STATIC_TOKEN_TTL_SECONDS,
        };
    }
}
