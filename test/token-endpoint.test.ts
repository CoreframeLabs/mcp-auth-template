import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import request from 'supertest';
import { decodeJwt } from 'jose';
import type { Express } from 'express';
import { randomBytes } from 'node:crypto';
import { createMockAuthServer, CLIENT_ASSERTION_TYPE } from '../src/mock-as/app.js';
import { ClientSecretStore, hashClientSecret } from '../src/auth/client-secret.js';
import type { AuthServerConfig } from '../src/config.js';
import { startTestClient, type TestClient } from './helpers/test-client.js';

const ISSUER = 'http://as.test';
const TOKEN_ENDPOINT = `${ISSUER}/token`;
const RESOURCE = 'http://rs.test/mcp';

const config: AuthServerConfig = {
    port: 0,
    issuerUrl: ISSUER,
    allowedResources: [RESOURCE],
    cimdAllowInsecure: true,
    cimdCacheTtlSeconds: 300,
};

let app: Express;
let client: TestClient;
const spawned: TestClient[] = [];

async function newClient(...args: Parameters<typeof startTestClient>): Promise<TestClient> {
    const c = await startTestClient(...args);
    spawned.push(c);
    return c;
}

beforeEach(async () => {
    ({ app } = await createMockAuthServer(config));
    client = await newClient();
});

afterEach(async () => {
    await Promise.all(spawned.splice(0).map((c) => c.close()));
});

function tokenRequest(fields: Record<string, string>) {
    return request(app).post('/token').type('form').send(fields);
}

async function validRequest(overrides: Record<string, string> = {}) {
    const assertion = await client.createAssertion({ audience: TOKEN_ENDPOINT });
    return tokenRequest({
        grant_type: 'client_credentials',
        client_assertion_type: CLIENT_ASSERTION_TYPE,
        client_assertion: assertion,
        resource: RESOURCE,
        ...overrides,
    });
}

describe('POST /token — client_credentials + private_key_jwt', () => {
    it('issues an access token to a correctly authenticated client', async () => {
        const res = await validRequest();
        expect(res.status).toBe(200);
        expect(res.body.token_type).toBe('Bearer');
        expect(res.body.expires_in).toBe(300);
        expect(typeof res.body.access_token).toBe('string');
    });

    it('scopes the issued token to the requested resource and client', async () => {
        const res = await validRequest();
        const claims = decodeJwt(res.body.access_token);
        expect(claims.iss).toBe(ISSUER);
        expect(claims.sub).toBe(client.clientId);
        expect(claims.aud).toBe(RESOURCE);
        expect(claims.jti).toBeTruthy();
    });

    it('marks token responses no-store', async () => {
        const res = await validRequest();
        expect(res.headers['cache-control']).toBe('no-store');
    });

    describe('rejects mismatched credentials', () => {
        it('rejects an assertion signed by a key the client does not publish', async () => {
            const assertion = await client.createAssertion({ audience: TOKEN_ENDPOINT, useWrongKey: true });
            const res = await tokenRequest({
                grant_type: 'client_credentials',
                client_assertion_type: CLIENT_ASSERTION_TYPE,
                client_assertion: assertion,
                resource: RESOURCE,
            });
            expect(res.status).toBe(401);
            expect(res.body.error).toBe('invalid_client');
        });

        it('rejects an assertion addressed to a different token endpoint', async () => {
            // Without an audience check the assertion could be captured by another
            // service and replayed here to impersonate the client.
            const assertion = await client.createAssertion({ audience: 'https://elsewhere.example/token' });
            const res = await tokenRequest({
                grant_type: 'client_credentials',
                client_assertion_type: CLIENT_ASSERTION_TYPE,
                client_assertion: assertion,
                resource: RESOURCE,
            });
            expect(res.status).toBe(401);
            expect(res.body.error).toBe('invalid_client');
        });

        it('rejects an expired assertion', async () => {
            const assertion = await client.createAssertion({
                audience: TOKEN_ENDPOINT,
                expiresInSeconds: -600,
            });
            const res = await tokenRequest({
                grant_type: 'client_credentials',
                client_assertion_type: CLIENT_ASSERTION_TYPE,
                client_assertion: assertion,
                resource: RESOURCE,
            });
            expect(res.status).toBe(401);
        });

        it('rejects an assertion whose subject is not its issuer', async () => {
            const assertion = await client.createAssertion({
                audience: TOKEN_ENDPOINT,
                subject: 'https://someone-else.example/',
            });
            const res = await tokenRequest({
                grant_type: 'client_credentials',
                client_assertion_type: CLIENT_ASSERTION_TYPE,
                client_assertion: assertion,
                resource: RESOURCE,
            });
            expect(res.status).toBe(401);
        });

        it('rejects a replayed assertion', async () => {
            const assertion = await client.createAssertion({ audience: TOKEN_ENDPOINT });
            const fields = {
                grant_type: 'client_credentials',
                client_assertion_type: CLIENT_ASSERTION_TYPE,
                client_assertion: assertion,
                resource: RESOURCE,
            };
            const first = await tokenRequest(fields);
            expect(first.status).toBe(200);

            const replay = await tokenRequest(fields);
            expect(replay.status).toBe(401);
            expect(replay.body.error_description).toMatch(/already been used/);
        });

        it('rejects a malformed assertion', async () => {
            const res = await tokenRequest({
                grant_type: 'client_credentials',
                client_assertion_type: CLIENT_ASSERTION_TYPE,
                client_assertion: 'not-a-jwt',
                resource: RESOURCE,
            });
            expect(res.status).toBe(401);
        });

        it('rejects a client whose metadata document cannot be resolved', async () => {
            const broken = await newClient({ clientIdOverride: 'https://attacker.example/' });
            const assertion = await broken.createAssertion({ audience: TOKEN_ENDPOINT });
            const res = await tokenRequest({
                grant_type: 'client_credentials',
                client_assertion_type: CLIENT_ASSERTION_TYPE,
                client_assertion: assertion,
                resource: RESOURCE,
            });
            expect(res.status).toBe(401);
            expect(res.body.error).toBe('invalid_client');
        });
    });

    describe('grant and target validation', () => {
        it('rejects an unsupported grant type', async () => {
            const res = await validRequest({ grant_type: 'authorization_code' });
            expect(res.status).toBe(400);
            expect(res.body.error).toBe('unsupported_grant_type');
        });

        it('rejects a request without private_key_jwt client authentication', async () => {
            const res = await validRequest({ client_assertion_type: 'client_secret_post' });
            expect(res.status).toBe(401);
            expect(res.body.error).toBe('invalid_client');
        });

        it('requires a resource parameter', async () => {
            const assertion = await client.createAssertion({ audience: TOKEN_ENDPOINT });
            const res = await tokenRequest({
                grant_type: 'client_credentials',
                client_assertion_type: CLIENT_ASSERTION_TYPE,
                client_assertion: assertion,
            });
            expect(res.status).toBe(400);
            expect(res.body.error).toBe('invalid_target');
        });

        it('refuses to mint tokens for an unknown resource', async () => {
            const res = await validRequest({ resource: 'http://not-ours.test/mcp' });
            expect(res.status).toBe(400);
            expect(res.body.error).toBe('invalid_target');
        });

        it('rejects a client not registered for client_credentials', async () => {
            const limited = await newClient({ grantTypes: ['authorization_code'] });
            const assertion = await limited.createAssertion({ audience: TOKEN_ENDPOINT });
            const res = await tokenRequest({
                grant_type: 'client_credentials',
                client_assertion_type: CLIENT_ASSERTION_TYPE,
                client_assertion: assertion,
                resource: RESOURCE,
            });
            expect(res.status).toBe(400);
            expect(res.body.error).toBe('unauthorized_client');
        });
    });

    describe('client_secret authentication (constant-time path)', () => {
        const SECRET = randomBytes(32).toString('base64url');
        let secretApp: Express;
        let secretClient: TestClient;

        beforeEach(async () => {
            secretClient = await newClient({ tokenEndpointAuthMethod: 'client_secret_basic' });
            secretClient.serveRaw(
                JSON.stringify({
                    client_id: secretClient.clientId,
                    token_endpoint_auth_method: 'client_secret_basic',
                    grant_types: ['client_credentials'],
                    scope: 'mcp:tools',
                }),
            );
            ({ app: secretApp } = await createMockAuthServer(config, {
                secrets: new ClientSecretStore([
                    { clientId: secretClient.clientId, hash: await hashClientSecret(SECRET) },
                ]),
            }));
        });

        const basicHeader = (id: string, secret: string) =>
            `Basic ${Buffer.from(`${encodeURIComponent(id)}:${encodeURIComponent(secret)}`).toString('base64')}`;

        const post = (header: string) =>
            request(secretApp)
                .post('/token')
                .set('authorization', header)
                .type('form')
                .send({ grant_type: 'client_credentials', resource: RESOURCE });

        it('issues a token to a client presenting the correct secret', async () => {
            const res = await post(basicHeader(secretClient.clientId, SECRET));
            expect(res.status).toBe(200);
            expect(decodeJwt(res.body.access_token).sub).toBe(secretClient.clientId);
        });

        it('rejects an incorrect secret', async () => {
            const res = await post(basicHeader(secretClient.clientId, randomBytes(32).toString('base64url')));
            expect(res.status).toBe(401);
            expect(res.body.error).toBe('invalid_client');
        });

        it('rejects a secret that is a prefix of the real one', async () => {
            const res = await post(basicHeader(secretClient.clientId, SECRET.slice(0, -1)));
            expect(res.status).toBe(401);
        });

        it('gives an unregistered client the same response as a wrong secret', async () => {
            // Identical bodies mean the endpoint cannot be used to enumerate
            // which client_ids are registered.
            const unknown = await post(basicHeader('https://not-registered.example/client', SECRET));
            const wrong = await post(basicHeader(secretClient.clientId, 'x'.repeat(43)));
            expect(unknown.status).toBe(wrong.status);
            expect(unknown.body).toEqual(wrong.body);
        });

        it('accepts client_secret_post as well as Basic', async () => {
            const client = await newClient({ tokenEndpointAuthMethod: 'client_secret_post' });
            client.serveRaw(
                JSON.stringify({
                    client_id: client.clientId,
                    token_endpoint_auth_method: 'client_secret_post',
                    grant_types: ['client_credentials'],
                    scope: 'mcp:tools',
                }),
            );
            const { app } = await createMockAuthServer(config, {
                secrets: new ClientSecretStore([
                    { clientId: client.clientId, hash: await hashClientSecret(SECRET) },
                ]),
            });
            const res = await request(app).post('/token').type('form').send({
                grant_type: 'client_credentials',
                resource: RESOURCE,
                client_id: client.clientId,
                client_secret: SECRET,
            });
            expect(res.status).toBe(200);
        });

        it('refuses a client authenticating with a mechanism it is not registered for', async () => {
            // The client's document says client_secret_basic; presenting a valid
            // assertion instead must not work.
            const assertion = await secretClient.createAssertion({ audience: TOKEN_ENDPOINT });
            const res = await request(secretApp).post('/token').type('form').send({
                grant_type: 'client_credentials',
                client_assertion_type: CLIENT_ASSERTION_TYPE,
                client_assertion: assertion,
                resource: RESOURCE,
            });
            expect(res.status).toBe(401);
        });

        it('rejects presenting two mechanisms at once', async () => {
            const res = await request(secretApp)
                .post('/token')
                .set('authorization', basicHeader(secretClient.clientId, SECRET))
                .type('form')
                .send({
                    grant_type: 'client_credentials',
                    resource: RESOURCE,
                    client_id: secretClient.clientId,
                    client_secret: SECRET,
                });
            expect(res.status).toBe(400);
            expect(res.body.error).toBe('invalid_request');
        });
    });

    describe('scope handling', () => {
        it('never grants a scope the client is not entitled to', async () => {
            const res = await validRequest({ scope: 'mcp:tools mcp:admin' });
            expect(res.status).toBe(200);
            expect(res.body.scope).toBe('mcp:tools');
            expect(decodeJwt(res.body.access_token).scope).toBe('mcp:tools');
        });

        it('rejects a request for only unentitled scopes', async () => {
            const res = await validRequest({ scope: 'mcp:admin' });
            expect(res.status).toBe(400);
            expect(res.body.error).toBe('invalid_scope');
        });
    });
});
