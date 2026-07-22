import { afterEach, describe, expect, it } from 'vitest';
import { CimdError, CimdResolver } from '../src/auth/cimd.js';
import { startTestClient, type TestClient } from './helpers/test-client.js';

const clients: TestClient[] = [];

async function newClient(...args: Parameters<typeof startTestClient>): Promise<TestClient> {
    const client = await startTestClient(...args);
    clients.push(client);
    return client;
}

afterEach(async () => {
    await Promise.all(clients.splice(0).map((c) => c.close()));
});

function resolver(overrides: Partial<ConstructorParameters<typeof CimdResolver>[0]> = {}) {
    return new CimdResolver({ allowInsecure: true, cacheTtlSeconds: 300, ...overrides });
}

/** A fetch stand-in for exercising wire-level responses we cannot easily produce. */
function fakeFetch(body: string, init: ResponseInit = {}): typeof fetch {
    return (async () =>
        new Response(body, {
            status: 200,
            headers: { 'content-type': 'application/json' },
            ...init,
        })) as unknown as typeof fetch;
}

describe('CimdResolver', () => {
    it('resolves a well-formed client metadata document', async () => {
        const client = await newClient();
        const doc = await resolver().resolve(client.clientId);
        expect(doc.client_id).toBe(client.clientId);
        expect(doc.token_endpoint_auth_method).toBe('private_key_jwt');
        expect(doc.jwks?.keys).toHaveLength(1);
    });

    it('resolves a document that delegates keys via jwks_uri', async () => {
        const client = await newClient({ useJwksUri: true });
        const doc = await resolver().resolve(client.clientId);
        expect(doc.jwks_uri).toBe(`${client.clientId}jwks.json`);
        expect(doc.jwks).toBeUndefined();
    });

    it('rejects a document whose client_id disagrees with its URL', async () => {
        // Without this check, any host could publish a document claiming to be
        // some other host's client_id and authenticate as them.
        const client = await newClient({ clientIdOverride: 'https://attacker.example/' });
        await expect(resolver().resolve(client.clientId)).rejects.toThrow(/does not match its URL/);
    });

    it('rejects a document that is not application/json', async () => {
        const client = await newClient();
        client.serveRaw('{"client_id":"x"}', 'text/html');
        await expect(resolver().resolve(client.clientId)).rejects.toThrow(/must be application\/json/);
    });

    it('rejects a body that is not valid JSON', async () => {
        const client = await newClient();
        client.serveRaw('not json at all');
        await expect(resolver().resolve(client.clientId)).rejects.toThrow(/not valid JSON/);
    });

    it('rejects a non-200 response', async () => {
        const client = await newClient();
        client.serveRaw('{}', 'application/json', 404);
        await expect(resolver().resolve(client.clientId)).rejects.toThrow(/HTTP 404/);
    });

    it('rejects a client that does not use private_key_jwt', async () => {
        const client = await newClient({ tokenEndpointAuthMethod: 'client_secret_post' });
        await expect(resolver().resolve(client.clientId)).rejects.toThrow(/only private_key_jwt/);
    });

    it('rejects a document carrying neither jwks nor jwks_uri', async () => {
        const client = await newClient();
        client.serveRaw(
            JSON.stringify({
                client_id: client.clientId,
                token_endpoint_auth_method: 'private_key_jwt',
            }),
        );
        await expect(resolver().resolve(client.clientId)).rejects.toThrow(/must supply jwks or jwks_uri/);
    });

    it('rejects a document carrying both jwks and jwks_uri', async () => {
        const client = await newClient();
        client.serveRaw(
            JSON.stringify({
                client_id: client.clientId,
                token_endpoint_auth_method: 'private_key_jwt',
                jwks: { keys: [{ kty: 'EC' }] },
                jwks_uri: `${client.clientId}jwks.json`,
            }),
        );
        await expect(resolver().resolve(client.clientId)).rejects.toThrow(/must not supply both/);
    });

    it('rejects an oversized document', async () => {
        const huge = JSON.stringify({ client_id: 'x', pad: 'a'.repeat(128 * 1024) });
        const r = resolver({ fetchImpl: fakeFetch(huge) });
        await expect(r.resolve('http://127.0.0.1:9/')).rejects.toThrow(/too large/);
    });

    describe('SSRF guard (allowInsecure = false)', () => {
        it('rejects plain http client_id URLs', async () => {
            await expect(resolver({ allowInsecure: false }).resolve('http://example.com/')).rejects.toThrow(
                /must use https/,
            );
        });

        it('rejects a client_id resolving to loopback', async () => {
            await expect(resolver({ allowInsecure: false }).resolve('https://127.0.0.1/')).rejects.toThrow(
                /non-public address/,
            );
        });

        it('rejects a client_id resolving to RFC 1918 space', async () => {
            await expect(resolver({ allowInsecure: false }).resolve('https://10.0.0.1/')).rejects.toThrow(
                /non-public address/,
            );
        });

        it('rejects the cloud instance metadata address', async () => {
            // 169.254.169.254 is the credential-theft target that makes SSRF
            // interesting to an attacker in the first place.
            await expect(resolver({ allowInsecure: false }).resolve('https://169.254.169.254/')).rejects.toThrow(
                /non-public address/,
            );
        });

        it('rejects IPv6 loopback', async () => {
            await expect(resolver({ allowInsecure: false }).resolve('https://[::1]/')).rejects.toThrow(
                /non-public address/,
            );
        });

        it('rejects a client_id carrying embedded credentials', async () => {
            await expect(resolver({ allowInsecure: false }).resolve('https://user:pw@example.com/')).rejects.toThrow(
                /must not contain credentials/,
            );
        });

        it('rejects a client_id carrying a fragment', async () => {
            await expect(resolver({ allowInsecure: false }).resolve('https://example.com/#frag')).rejects.toThrow(
                /must not contain a fragment/,
            );
        });
    });

    describe('caching', () => {
        it('serves repeat resolutions from cache', async () => {
            const client = await newClient();
            const r = resolver();
            await r.resolve(client.clientId);
            await r.resolve(client.clientId);
            await r.resolve(client.clientId);
            expect(client.fetchCount()).toBe(1);
        });

        it('re-fetches once the TTL has elapsed', async () => {
            const client = await newClient();
            const r = resolver({ cacheTtlSeconds: 1 });
            await r.resolve(client.clientId);
            r.clearCache();
            await r.resolve(client.clientId);
            expect(client.fetchCount()).toBe(2);
        });

        it('negative-caches failures so a hostile client_id cannot amplify traffic', async () => {
            const client = await newClient({ clientIdOverride: 'https://attacker.example/' });
            const r = resolver();
            await expect(r.resolve(client.clientId)).rejects.toThrow(CimdError);
            await expect(r.resolve(client.clientId)).rejects.toThrow(CimdError);
            expect(client.fetchCount()).toBe(1);
        });
    });
});
