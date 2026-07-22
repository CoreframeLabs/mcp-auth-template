import { createLocalJWKSet, createRemoteJWKSet, decodeJwt, jwtVerify, type JSONWebKeySet } from 'jose';
import type { ClientSecretStore } from '../auth/client-secret.js';
import { ClientAuthError, type ClientAuthentication } from '../auth/client-authentication.js';
import type { CimdResolver, ClientMetadata } from '../auth/cimd.js';

/**
 * Establishes which client is calling, and proves it.
 *
 * Both supported mechanisms end in the same place — a verified client_id and its
 * metadata document — but they prove identity very differently:
 *
 *   private_key_jwt      possession of a private key whose public half the
 *                        client publishes at its client_id URL
 *   client_secret_*      possession of a shared secret, verified against a
 *                        stored scrypt hash in constant time
 *
 * Every failure path raises ClientAuthError with the same generic message. The
 * caller must not distinguish "unknown client" from "bad credential" in its
 * response: doing so turns the token endpoint into a client_id oracle.
 */

export interface VerifiedClient {
    clientId: string;
    metadata: ClientMetadata;
}

export interface ReplayGuard {
    claim(jti: string, expiresAtMs: number): boolean;
}

export interface VerifyDeps {
    resolver: CimdResolver;
    secrets: ClientSecretStore;
    replayGuard: ReplayGuard;
    tokenEndpoint: string;
}

const GENERIC_FAILURE = 'client authentication failed';

async function resolveMetadata(resolver: CimdResolver, clientId: string): Promise<ClientMetadata> {
    try {
        return await resolver.resolve(clientId);
    } catch {
        throw new ClientAuthError(GENERIC_FAILURE);
    }
}

async function verifyPrivateKeyJwt(deps: VerifyDeps, assertion: string): Promise<VerifiedClient> {
    // Read `iss` unverified purely to learn which client_id to resolve. Nothing
    // is trusted until the signature is checked against that client's own keys.
    let clientId: string;
    try {
        clientId = decodeJwt(assertion).iss ?? '';
    } catch {
        throw new ClientAuthError(GENERIC_FAILURE);
    }
    if (!clientId) throw new ClientAuthError(GENERIC_FAILURE);

    const metadata = await resolveMetadata(deps.resolver, clientId);
    if (metadata.token_endpoint_auth_method !== 'private_key_jwt') {
        throw new ClientAuthError(GENERIC_FAILURE);
    }

    const keys = metadata.jwks
        ? createLocalJWKSet(metadata.jwks as unknown as JSONWebKeySet)
        : createRemoteJWKSet(new URL(metadata.jwks_uri!), { cacheMaxAge: 600_000, timeoutDuration: 5_000 });

    let claims;
    try {
        ({ payload: claims } = await jwtVerify(assertion, keys, {
            issuer: clientId,
            subject: clientId,
            audience: deps.tokenEndpoint,
            algorithms: ['ES256', 'RS256'],
            clockTolerance: 5,
            maxTokenAge: '5 minutes',
            requiredClaims: ['iss', 'sub', 'aud', 'exp', 'jti'],
        }));
    } catch {
        throw new ClientAuthError(GENERIC_FAILURE);
    }

    if (!deps.replayGuard.claim(claims.jti!, (claims.exp ?? 0) * 1000)) {
        throw new ClientAuthError('client_assertion has already been used');
    }

    return { clientId, metadata };
}

async function verifyClientSecretAuth(
    deps: VerifyDeps,
    auth: Extract<ClientAuthentication, { method: 'client_secret_basic' | 'client_secret_post' }>,
): Promise<VerifiedClient> {
    // The secret is verified BEFORE the metadata document is fetched. An
    // unauthenticated caller must not be able to make this server issue an
    // outbound HTTP request just by naming a client_id.
    const matches = await deps.secrets.verify(auth.clientId, auth.secret);
    if (!matches) throw new ClientAuthError(GENERIC_FAILURE);

    const metadata = await resolveMetadata(deps.resolver, auth.clientId);
    if (metadata.token_endpoint_auth_method !== auth.method) {
        // A client registered for one mechanism may not authenticate with
        // another, even holding a valid credential for it.
        throw new ClientAuthError(GENERIC_FAILURE);
    }
    return { clientId: auth.clientId, metadata };
}

export async function verifyClient(deps: VerifyDeps, auth: ClientAuthentication): Promise<VerifiedClient> {
    return auth.method === 'private_key_jwt'
        ? verifyPrivateKeyJwt(deps, auth.assertion)
        : verifyClientSecretAuth(deps, auth);
}
