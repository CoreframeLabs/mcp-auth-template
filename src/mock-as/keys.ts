import { exportJWK, generateKeyPair, type JWK, type KeyObject } from 'jose';
import { randomUUID } from 'node:crypto';
import { ACCESS_TOKEN_ALG } from '../auth/verifiers.js';

export interface SigningKey {
    kid: string;
    alg: string;
    privateKey: KeyObject | CryptoKey;
    publicJwk: JWK;
}

/**
 * Generates an ephemeral ES256 signing key.
 *
 * Ephemeral is the point: the mock authorization server mints a new key on every
 * boot, so there is no long-lived private key anywhere in this repository to
 * accidentally commit. Restarting the AS invalidates previously issued tokens,
 * which is correct behaviour for a development server.
 */
export async function generateSigningKey(): Promise<SigningKey> {
    const { privateKey, publicKey } = await generateKeyPair(ACCESS_TOKEN_ALG, { extractable: true });
    const publicJwk = await exportJWK(publicKey);
    const kid = randomUUID();
    publicJwk.kid = kid;
    publicJwk.alg = ACCESS_TOKEN_ALG;
    publicJwk.use = 'sig';
    return { kid, alg: ACCESS_TOKEN_ALG, privateKey, publicJwk };
}
