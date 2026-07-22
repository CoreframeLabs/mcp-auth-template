import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Server } from 'node:http';
import { randomBytes } from 'node:crypto';
import { createResourceServerApp } from '../src/app.js';
import { StaticTokenVerifier } from '../src/auth/verifiers.js';
import type { ResourceServerConfig } from '../src/config.js';
import { close, getFreePort, listen } from './helpers/net.js';

const STATIC_TOKEN = randomBytes(32).toString('base64url');

let server: Server;
let shutdown: () => Promise<void>;
let resourceUrl: string;

beforeAll(async () => {
    const port = await getFreePort();
    resourceUrl = `http://127.0.0.1:${port}/mcp`;
    const config: ResourceServerConfig = {
        port,
        resourceUrl,
        issuerUrl: 'http://as.test',
        jwksUri: undefined,
        requiredScopes: ['mcp:tools'],
        authMode: 'static',
        staticToken: STATIC_TOKEN,
        cimdAllowInsecure: true,
        cimdCacheTtlSeconds: 300,
    };
    const rs = createResourceServerApp(config);
    shutdown = rs.shutdown;
    server = await listen(rs.app, port);
});

afterAll(async () => {
    await shutdown?.();
    if (server) await close(server);
});

function initialize(token: string | null) {
    return fetch(resourceUrl, {
        method: 'POST',
        headers: {
            'content-type': 'application/json',
            accept: 'application/json, text/event-stream',
            ...(token ? { authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({
            jsonrpc: '2.0',
            id: 1,
            method: 'initialize',
            params: {
                protocolVersion: '2025-06-18',
                capabilities: {},
                clientInfo: { name: 'static-test', version: '0.0.0' },
            },
        }),
    });
}

describe('static token mode', () => {
    it('accepts the configured token', async () => {
        const res = await initialize(STATIC_TOKEN);
        expect(res.status).toBe(200);
        expect(res.headers.get('mcp-session-id')).toBeTruthy();
    });

    it('rejects a mismatched token', async () => {
        const res = await initialize(randomBytes(32).toString('base64url'));
        expect(res.status).toBe(401);
    });

    it('rejects a token that is a prefix of the real one', async () => {
        const res = await initialize(STATIC_TOKEN.slice(0, -1));
        expect(res.status).toBe(401);
    });

    it('rejects a whitespace-padded token at the verifier', async () => {
        // Not asserted over HTTP: RFC 9110 strips optional whitespace around
        // header field values, so a padded token never arrives padded. The
        // property worth pinning is that the comparison itself is exact.
        const verifier = new StaticTokenVerifier({
            token: STATIC_TOKEN,
            resource: resourceUrl,
            scopes: ['mcp:tools'],
        });
        await expect(verifier.verifyAccessToken(`${STATIC_TOKEN} `)).rejects.toThrow();
        await expect(verifier.verifyAccessToken(` ${STATIC_TOKEN}`)).rejects.toThrow();
        await expect(verifier.verifyAccessToken(STATIC_TOKEN)).resolves.toMatchObject({
            clientId: 'static-dev-client',
        });
    });

    it('rejects a missing token', async () => {
        const res = await initialize(null);
        expect(res.status).toBe(401);
    });

    it('refuses to construct a verifier with a weak token', () => {
        expect(
            () => new StaticTokenVerifier({ token: 'too-short', resource: resourceUrl, scopes: ['mcp:tools'] }),
        ).toThrow(/at least 32 characters/);
    });
});
