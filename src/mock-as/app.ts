import express, { type Express, type Response } from 'express';
import { randomUUID } from 'node:crypto';
import { SignJWT } from 'jose';
import { CimdResolver } from '../auth/cimd.js';
import { ACCESS_TOKEN_ALG } from '../auth/verifiers.js';
import {
    ClientAuthError,
    parseClientAuthentication,
    SUPPORTED_AUTH_METHODS,
    CLIENT_ASSERTION_TYPE,
} from '../auth/client-authentication.js';
import { ClientSecretStore } from '../auth/client-secret.js';
import { verifyClient } from './verify-client.js';
import { canonicalResourceUrl, type AuthServerConfig } from '../config.js';
import { generateSigningKey, type SigningKey } from './keys.js';

export { CLIENT_ASSERTION_TYPE };
export const ACCESS_TOKEN_TTL_SECONDS = 300;

/** Client assertions are single-use; this remembers the ones already spent. */
class JtiReplayGuard {
    private readonly seen = new Map<string, number>();

    /** Returns false if this jti has been presented before. */
    claim(jti: string, expiresAtMs: number): boolean {
        this.prune();
        if (this.seen.has(jti)) return false;
        this.seen.set(jti, expiresAtMs);
        return true;
    }

    private prune(): void {
        const now = Date.now();
        for (const [jti, expiry] of this.seen) {
            if (expiry <= now) this.seen.delete(jti);
        }
    }
}

function oauthError(res: Response, status: number, error: string, description: string): void {
    res.status(status).set('cache-control', 'no-store').json({ error, error_description: description });
}

export interface MockAuthServer {
    app: Express;
    signingKey: SigningKey;
    resolver: CimdResolver;
}

/**
 * A deliberately small OAuth 2.1 authorization server covering exactly the
 * server-to-server path an MCP client needs:
 *
 *   client_credentials grant + private_key_jwt client authentication,
 *   where the client is identified by a Client ID Metadata Document URL.
 *
 * It is a *mock*: tokens are in-memory, keys are ephemeral, there is no
 * persistence, no rate limiting, and no admin surface. Do not deploy it.
 */
export async function createMockAuthServer(
    config: AuthServerConfig,
    options: {
        /**
         * Restricts which client_ids may be dereferenced at all. Required for any
         * publicly reachable deployment — see CimdOptions.allowlist.
         */
        cimdAllowlist?: (clientId: string) => boolean;
        /** See CimdOptions.internalRewrite. Demo/self-hosting deployments only. */
        cimdInternalRewrite?: (clientId: string) => string | null;
        /**
         * Registered client secrets, stored as scrypt hashes. Clients whose
         * metadata declares client_secret_basic/post are verified against this.
         */
        secrets?: ClientSecretStore;
    } = {},
): Promise<MockAuthServer> {
    const secrets = options.secrets ?? new ClientSecretStore();
    const signingKey = await generateSigningKey();
    const resolver = new CimdResolver({
        allowInsecure: config.cimdAllowInsecure,
        cacheTtlSeconds: config.cimdCacheTtlSeconds,
        ...(options.cimdAllowlist ? { allowlist: options.cimdAllowlist } : {}),
        ...(options.cimdInternalRewrite ? { internalRewrite: options.cimdInternalRewrite } : {}),
    });
    const replayGuard = new JtiReplayGuard();
    const tokenEndpoint = `${config.issuerUrl}/token`;

    const app = express();
    app.disable('x-powered-by');
    app.use(express.urlencoded({ extended: false, limit: '32kb' }));
    app.use(express.json({ limit: '32kb' }));

    app.get('/.well-known/oauth-authorization-server', (_req, res) => {
        res.set('cache-control', 'public, max-age=300').json({
            issuer: config.issuerUrl,
            authorization_endpoint: `${config.issuerUrl}/authorize`,
            token_endpoint: tokenEndpoint,
            jwks_uri: `${config.issuerUrl}/jwks.json`,
            grant_types_supported: ['client_credentials'],
            token_endpoint_auth_methods_supported: SUPPORTED_AUTH_METHODS,
            token_endpoint_auth_signing_alg_values_supported: ['ES256', 'RS256'],
            response_types_supported: [],
            scopes_supported: ['mcp:tools'],
            resource_indicators_supported: true,
            client_id_metadata_document_supported: true,
        });
    });

    // Advertised for metadata completeness, but this mock implements only the
    // server-to-server grant. Answer honestly instead of 404-ing.
    app.get('/authorize', (_req, res) => {
        oauthError(
            res,
            501,
            'unsupported_response_type',
            'this mock authorization server implements only the client_credentials grant',
        );
    });

    app.get('/jwks.json', (_req, res) => {
        res.set('cache-control', 'public, max-age=300').json({ keys: [signingKey.publicJwk] });
    });

    app.post('/token', async (req, res) => {
        const body = (req.body ?? {}) as Record<string, unknown>;

        if (body['grant_type'] !== 'client_credentials') {
            return oauthError(res, 400, 'unsupported_grant_type', 'only client_credentials is supported');
        }

        // RFC 8707: the client must name the resource it wants a token for, and
        // we only mint tokens narrowly scoped to that audience. A token for one
        // MCP server must never be replayable against another.
        const resource = body['resource'];
        if (typeof resource !== 'string' || resource.length === 0) {
            return oauthError(res, 400, 'invalid_target', 'resource parameter is required');
        }
        let requestedResource: string;
        try {
            requestedResource = canonicalResourceUrl(resource);
        } catch {
            return oauthError(res, 400, 'invalid_target', 'resource must be an absolute URI');
        }
        if (!config.allowedResources.includes(requestedResource)) {
            return oauthError(res, 400, 'invalid_target', 'unknown resource identifier');
        }

        // Identify and prove the client. Both mechanisms funnel through the same
        // generic failure so the endpoint cannot be used to enumerate client_ids.
        let verified;
        try {
            const presented = parseClientAuthentication(req);
            verified = await verifyClient({ resolver, secrets, replayGuard, tokenEndpoint }, presented);
        } catch (err) {
            if (err instanceof ClientAuthError) {
                const status = err.oauthError === 'invalid_request' ? 400 : 401;
                return oauthError(res, status, err.oauthError, err.message);
            }
            throw err;
        }
        const { clientId, metadata: doc } = verified;

        if (!doc.grant_types.includes('client_credentials')) {
            return oauthError(res, 400, 'unauthorized_client', 'client is not registered for client_credentials');
        }

        // Grant the intersection of what was asked for and what the client's
        // metadata document says it is allowed to hold. Never grant more.
        const allowed = (doc.scope ?? 'mcp:tools').split(/\s+/).filter(Boolean);
        const requested = typeof body['scope'] === 'string' ? body['scope'].split(/\s+/).filter(Boolean) : allowed;
        const granted = requested.filter((s) => allowed.includes(s));
        if (granted.length === 0) {
            return oauthError(res, 400, 'invalid_scope', 'no requested scope is permitted for this client');
        }

        const accessToken = await new SignJWT({ scope: granted.join(' ') })
            .setProtectedHeader({ alg: ACCESS_TOKEN_ALG, kid: signingKey.kid, typ: 'at+jwt' })
            .setIssuer(config.issuerUrl)
            .setSubject(clientId)
            .setAudience(requestedResource)
            .setIssuedAt()
            .setExpirationTime(`${ACCESS_TOKEN_TTL_SECONDS}s`)
            .setJti(randomUUID())
            .sign(signingKey.privateKey);

        res.set('cache-control', 'no-store').json({
            access_token: accessToken,
            token_type: 'Bearer',
            expires_in: ACCESS_TOKEN_TTL_SECONDS,
            scope: granted.join(' '),
        });
    });

    return { app, signingKey, resolver };
}
