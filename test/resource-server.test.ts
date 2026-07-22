import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Server } from 'node:http';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { createMockAuthServer, CLIENT_ASSERTION_TYPE } from '../src/mock-as/app.js';
import { createResourceServerApp } from '../src/app.js';
import type { ResourceServerConfig } from '../src/config.js';
import { startTestClient, type TestClient } from './helpers/test-client.js';
import { close, getFreePort, listen } from './helpers/net.js';

let asServer: Server;
let rsServer: Server;
let shutdownRs: () => Promise<void>;

let issuer: string;
let resourceUrl: string;
let otherResourceUrl: string;

let clientA: TestClient;
let clientB: TestClient;
/** Entitled only to mcp:read, so its tokens lack the required mcp:tools scope. */
let lowScopeClient: TestClient;

async function getToken(client: TestClient, resource = resourceUrl): Promise<string> {
    const assertion = await client.createAssertion({ audience: `${issuer}/token` });
    const res = await fetch(`${issuer}/token`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
            grant_type: 'client_credentials',
            client_assertion_type: CLIENT_ASSERTION_TYPE,
            client_assertion: assertion,
            resource,
        }),
    });
    const body = (await res.json()) as { access_token?: string; error?: string };
    if (!res.ok || !body.access_token) {
        throw new Error(`token request failed: ${res.status} ${JSON.stringify(body)}`);
    }
    return body.access_token;
}

async function connect(token: string): Promise<{ client: Client; transport: StreamableHTTPClientTransport }> {
    const transport = new StreamableHTTPClientTransport(new URL(resourceUrl), {
        requestInit: { headers: { authorization: `Bearer ${token}` } },
    });
    const client = new Client({ name: 'test-client', version: '0.0.0' });
    await client.connect(transport);
    return { client, transport };
}

beforeAll(async () => {
    const asPort = await getFreePort();
    const rsPort = await getFreePort();
    issuer = `http://127.0.0.1:${asPort}`;
    resourceUrl = `http://127.0.0.1:${rsPort}/mcp`;
    otherResourceUrl = `http://127.0.0.1:${rsPort}/other`;

    const as = await createMockAuthServer({
        port: asPort,
        issuerUrl: issuer,
        allowedResources: [resourceUrl, otherResourceUrl],
        cimdAllowInsecure: true,
        cimdCacheTtlSeconds: 300,
    });
    asServer = await listen(as.app, asPort);

    const rsConfig: ResourceServerConfig = {
        port: rsPort,
        resourceUrl,
        issuerUrl: issuer,
        jwksUri: `${issuer}/jwks.json`,
        requiredScopes: ['mcp:tools'],
        authMode: 'jwt',
        staticToken: undefined,
        cimdAllowInsecure: true,
        cimdCacheTtlSeconds: 300,
    };
    const rs = createResourceServerApp(rsConfig);
    shutdownRs = rs.shutdown;
    rsServer = await listen(rs.app, rsPort);

    clientA = await startTestClient();
    clientB = await startTestClient();
    lowScopeClient = await startTestClient({ scope: 'mcp:read' });
});

afterAll(async () => {
    await shutdownRs?.();
    await Promise.all([clientA?.close(), clientB?.close(), lowScopeClient?.close()]);
    if (rsServer) await close(rsServer);
    if (asServer) await close(asServer);
});

describe('resource server — happy path', () => {
    it('completes the MCP initialize handshake with a valid token', async () => {
        const { client, transport } = await connect(await getToken(clientA));
        expect(transport.sessionId).toBeTruthy();
        await client.close();
    });

    it('exposes the registered tools', async () => {
        const { client } = await connect(await getToken(clientA));
        const { tools } = await client.listTools();
        expect(tools.map((t) => t.name).sort()).toEqual(['echo', 'whoami']);
        await client.close();
    });

    it('propagates the verified identity all the way into tool code', async () => {
        const { client } = await connect(await getToken(clientA));
        const result = (await client.callTool({ name: 'whoami', arguments: {} })) as {
            content: { type: string; text: string }[];
        };
        const identity = JSON.parse(result.content[0]!.text);
        expect(identity.clientId).toBe(clientA.clientId);
        expect(identity.scopes).toContain('mcp:tools');
        expect(identity.resource).toBe(resourceUrl);
        await client.close();
    });

    it('round-trips a tool call', async () => {
        const { client } = await connect(await getToken(clientA));
        const result = (await client.callTool({ name: 'echo', arguments: { message: 'hello coreframe' } })) as {
            content: { type: string; text: string }[];
        };
        expect(result.content[0]!.text).toBe('hello coreframe');
        await client.close();
    });

    it('serves protected resource metadata for discovery', async () => {
        const res = await fetch(`${new URL(resourceUrl).origin}/.well-known/oauth-protected-resource/mcp`);
        expect(res.status).toBe(200);
        const body = (await res.json()) as { authorization_servers?: string[]; resource?: string };
        expect(body.resource).toBe(resourceUrl);
        expect(body.authorization_servers).toContain(issuer);
    });

    it('reports health without authentication', async () => {
        const res = await fetch(`${new URL(resourceUrl).origin}/healthz`);
        expect(res.status).toBe(200);
        expect(((await res.json()) as { status: string }).status).toBe('ok');
    });
});

/** Raw JSON-RPC POST, bypassing the client SDK so we can assert on status codes. */
async function rawPost(headers: Record<string, string>) {
    return fetch(resourceUrl, {
        method: 'POST',
        headers: {
            'content-type': 'application/json',
            accept: 'application/json, text/event-stream',
            ...headers,
        },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }),
    });
}

describe('resource server — token rejection', () => {
    it('rejects a request with no Authorization header', async () => {
        const res = await rawPost({});
        expect(res.status).toBe(401);
    });

    it('points an unauthenticated caller at the resource metadata document', async () => {
        const res = await rawPost({});
        const header = res.headers.get('www-authenticate') ?? '';
        expect(header).toMatch(/Bearer/);
        expect(header).toMatch(/resource_metadata=/);
    });

    it('rejects a structurally invalid token', async () => {
        const res = await rawPost({ authorization: 'Bearer not-a-real-token' });
        expect(res.status).toBe(401);
    });

    it('rejects an empty bearer token', async () => {
        const res = await rawPost({ authorization: 'Bearer ' });
        expect(res.status).toBe(401);
    });

    it('rejects a token minted for a different resource', async () => {
        // The audience binding is what stops a token issued for one MCP server
        // being replayed against another by a confused or malicious client.
        const token = await getToken(clientA, otherResourceUrl);
        const res = await rawPost({ authorization: `Bearer ${token}` });
        expect(res.status).toBe(401);
    });

    it('rejects a token signed by an untrusted issuer', async () => {
        const rogueAs = await createMockAuthServer({
            port: 0,
            issuerUrl: 'http://rogue.test',
            allowedResources: [resourceUrl],
            cimdAllowInsecure: true,
            cimdCacheTtlSeconds: 300,
        });
        const rogueServer = await listen(rogueAs.app, await getFreePort());
        try {
            const assertion = await clientA.createAssertion({ audience: 'http://rogue.test/token' });
            const rogueRes = await fetch(
                `http://127.0.0.1:${(rogueServer.address() as { port: number }).port}/token`,
                {
                    method: 'POST',
                    headers: { 'content-type': 'application/x-www-form-urlencoded' },
                    body: new URLSearchParams({
                        grant_type: 'client_credentials',
                        client_assertion_type: CLIENT_ASSERTION_TYPE,
                        client_assertion: assertion,
                        resource: resourceUrl,
                    }),
                },
            );
            const { access_token } = (await rogueRes.json()) as { access_token: string };
            expect(access_token).toBeTruthy();

            const res = await rawPost({ authorization: `Bearer ${access_token}` });
            expect(res.status).toBe(401);
        } finally {
            await close(rogueServer);
        }
    });

    it('rejects a token lacking the required scope', async () => {
        const token = await getToken(lowScopeClient);
        const res = await rawPost({ authorization: `Bearer ${token}` });
        expect(res.status).toBe(403);
    });

    it('does not leak why a token failed', async () => {
        // "expired" vs "wrong audience" vs "bad signature" all collapse to the
        // same message, so a probing caller learns nothing from the difference.
        const wrongResource = await rawPost({ authorization: `Bearer ${await getToken(clientA, otherResourceUrl)}` });
        const garbage = await rawPost({ authorization: 'Bearer not-a-real-token' });
        expect(await wrongResource.json()).toEqual(await garbage.json());
    });
});

describe('resource server — session isolation', () => {
    it('refuses to let one client attach to another client’s session', async () => {
        const { client, transport } = await connect(await getToken(clientA));
        const sessionId = transport.sessionId!;
        expect(sessionId).toBeTruthy();

        const res = await rawPost({
            authorization: `Bearer ${await getToken(clientB)}`,
            'mcp-session-id': sessionId,
        });
        expect(res.status).toBe(404);

        // …and client A's own session still works afterwards.
        const stillWorks = await client.listTools();
        expect(stillWorks.tools.length).toBeGreaterThan(0);
        await client.close();
    });

    it('rejects an unknown session id', async () => {
        const res = await rawPost({
            authorization: `Bearer ${await getToken(clientA)}`,
            'mcp-session-id': '00000000-0000-4000-8000-000000000000',
        });
        expect(res.status).toBe(404);
    });

    it('rejects a non-initialize request that carries no session id', async () => {
        const res = await rawPost({ authorization: `Bearer ${await getToken(clientA)}` });
        expect(res.status).toBe(400);
    });
});
