import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { randomUUID } from 'node:crypto';
import { exportJWK, generateKeyPair, SignJWT, type JWK, type KeyObject } from 'jose';

export interface AssertionOverrides {
    audience?: string;
    issuer?: string;
    subject?: string;
    jti?: string;
    /** Seconds until expiry. Negative produces an already-expired assertion. */
    expiresInSeconds?: number;
    /** Sign with a key the published document does NOT list. */
    useWrongKey?: boolean;
}

export interface TestClient {
    /** The client_id — an http URL serving this client's metadata document. */
    clientId: string;
    /** How many times the metadata document has been fetched. */
    fetchCount: () => number;
    /** Replace the served document (or serve malformed bytes). */
    serveRaw: (body: string, contentType?: string, status?: number) => void;
    createAssertion: (overrides?: AssertionOverrides) => Promise<string>;
    close: () => Promise<void>;
}

/**
 * A real HTTP server publishing a Client ID Metadata Document, plus the private
 * key to sign matching client assertions.
 *
 * Deliberately a real socket rather than a fetch mock: CIMD's security depends
 * on how content-type, size and redirects are handled on the wire, and a mock
 * would let those regress silently.
 */
export async function startTestClient(
    options: {
        scope?: string;
        grantTypes?: string[];
        tokenEndpointAuthMethod?: string;
        useJwksUri?: boolean;
        /** Publish a client_id that disagrees with the fetch URL. */
        clientIdOverride?: string;
    } = {},
): Promise<TestClient> {
    const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
    const wrong = await generateKeyPair('ES256', { extractable: true });

    const publicJwk: JWK = await exportJWK(publicKey);
    publicJwk.kid = randomUUID();
    publicJwk.alg = 'ES256';
    publicJwk.use = 'sig';

    let fetchCount = 0;
    let rawOverride: { body: string; contentType: string; status: number } | null = null;
    let clientId = '';

    const server = createServer((req, res) => {
        if (req.url?.startsWith('/jwks.json')) {
            res.writeHead(200, { 'content-type': 'application/json' });
            res.end(JSON.stringify({ keys: [publicJwk] }));
            return;
        }
        fetchCount += 1;
        if (rawOverride) {
            res.writeHead(rawOverride.status, { 'content-type': rawOverride.contentType });
            res.end(rawOverride.body);
            return;
        }
        const doc: Record<string, unknown> = {
            client_id: options.clientIdOverride ?? clientId,
            client_name: 'Coreframe Test Client',
            grant_types: options.grantTypes ?? ['client_credentials'],
            token_endpoint_auth_method: options.tokenEndpointAuthMethod ?? 'private_key_jwt',
            scope: options.scope ?? 'mcp:tools',
        };
        if (options.useJwksUri) {
            doc['jwks_uri'] = `${clientId}jwks.json`;
        } else {
            doc['jwks'] = { keys: [publicJwk] };
        }
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify(doc));
    });

    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address() as AddressInfo;
    clientId = `http://127.0.0.1:${port}/`;

    return {
        get clientId() {
            return clientId;
        },
        fetchCount: () => fetchCount,
        serveRaw: (body, contentType = 'application/json', status = 200) => {
            rawOverride = { body, contentType, status };
        },
        createAssertion: async (overrides: AssertionOverrides = {}) => {
            const key: KeyObject | CryptoKey = overrides.useWrongKey ? wrong.privateKey : privateKey;
            const expiresIn = overrides.expiresInSeconds ?? 60;
            const now = Math.floor(Date.now() / 1000);
            return new SignJWT({})
                .setProtectedHeader({ alg: 'ES256', kid: publicJwk.kid })
                .setIssuer(overrides.issuer ?? clientId)
                .setSubject(overrides.subject ?? clientId)
                .setAudience(overrides.audience ?? 'https://example.invalid/token')
                .setIssuedAt(now)
                .setExpirationTime(now + expiresIn)
                .setJti(overrides.jti ?? randomUUID())
                .sign(key);
        },
        close: () =>
            new Promise<void>((resolve, reject) => {
                server.close((err) => (err ? reject(err) : resolve()));
            }),
    };
}
