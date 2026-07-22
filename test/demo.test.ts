import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import type { Server } from 'node:http';
import { CimdResolver } from '../src/auth/cimd.js';
import { createDemoServer } from '../src/demo/server.js';
import { SCENARIOS } from '../src/demo/scenarios.js';
import { close, getFreePort, listen } from './helpers/net.js';

describe('CIMD allowlist', () => {
    it('refuses a non-allowlisted client_id WITHOUT making any request', async () => {
        // The point of the allowlist is that a public deployment never becomes a
        // fetch-any-URL oracle. A rejection that still performs the fetch would
        // defeat it entirely, so assert on the fetch never happening.
        const fetchImpl = vi.fn(async () => {
            throw new Error('fetch must not be called for a disallowed client_id');
        }) as unknown as typeof fetch;

        const resolver = new CimdResolver({
            allowInsecure: true,
            cacheTtlSeconds: 300,
            fetchImpl,
            allowlist: (id) => id === 'https://allowed.example/client',
        });

        await expect(resolver.resolve('https://attacker.example/probe')).rejects.toThrow(/not permitted/);
        expect(fetchImpl).not.toHaveBeenCalled();
    });

    it('does not block an allowlisted client_id', async () => {
        const resolver = new CimdResolver({
            allowInsecure: true,
            cacheTtlSeconds: 300,
            fetchImpl: (async () =>
                new Response(
                    JSON.stringify({
                        client_id: 'https://allowed.example/client',
                        token_endpoint_auth_method: 'private_key_jwt',
                        jwks: { keys: [{ kty: 'EC' }] },
                    }),
                    { status: 200, headers: { 'content-type': 'application/json' } },
                )) as unknown as typeof fetch,
            allowlist: (id) => id === 'https://allowed.example/client',
        });

        const doc = await resolver.resolve('https://allowed.example/client');
        expect(doc.client_id).toBe('https://allowed.example/client');
    });
});

describe('demo server behind a proxy (public URL != listen address)', () => {
    // Reproduces the containerised deployment: PUBLIC_URL is an external domain
    // that does not resolve from inside the process. Everything the demo does to
    // itself must go over loopback, while every identity stays public. Getting
    // this wrong fails only once deployed, which is the worst place to find out.
    let server: Server;
    let shutdown: () => Promise<void>;
    let port: number;

    const PUBLIC = 'https://mcp-auth.demo.invalid';

    beforeAll(async () => {
        port = await getFreePort();
        const demo = await createDemoServer({
            publicUrl: PUBLIC,
            port,
            allowInsecure: false,
            internalUrl: `http://127.0.0.1:${port}`,
        });
        shutdown = demo.shutdown;
        server = await listen(demo.app, port);
    });

    afterAll(async () => {
        await shutdown?.();
        if (server) await close(server);
    });

    it('completes the happy path without resolving the public origin', async () => {
        const res = await fetch(`http://127.0.0.1:${port}/demo/run/happy-path`, { method: 'POST' });
        const result = (await res.json()) as { succeeded: boolean; summary: string };
        expect(result.succeeded).toBe(true);
    });

    it('publishes client_ids under the PUBLIC origin, not the internal one', async () => {
        const res = await fetch(`http://127.0.0.1:${port}/demo/clients/well-behaved`);
        const doc = (await res.json()) as { client_id: string };
        expect(doc.client_id).toBe(`${PUBLIC}/demo/clients/well-behaved`);
    });

    it('advertises the PUBLIC resource identifier for discovery', async () => {
        const res = await fetch(`http://127.0.0.1:${port}/.well-known/oauth-protected-resource/mcp`);
        const body = (await res.json()) as { resource: string; authorization_servers: string[] };
        expect(body.resource).toBe(`${PUBLIC}/mcp`);
        expect(body.authorization_servers).toContain(PUBLIC);
    });
});

describe('demo server', () => {
    let server: Server;
    let shutdown: () => Promise<void>;
    let baseUrl: string;

    beforeAll(async () => {
        const port = await getFreePort();
        baseUrl = `http://localhost:${port}`;
        const demo = await createDemoServer({ publicUrl: baseUrl, port, allowInsecure: true });
        shutdown = demo.shutdown;
        server = await listen(demo.app, port);
    });

    afterAll(async () => {
        await shutdown?.();
        if (server) await close(server);
    });

    it('serves a valid Client ID Metadata Document whose client_id matches its URL', async () => {
        const url = `${baseUrl}/demo/clients/well-behaved`;
        const res = await fetch(url);
        expect(res.status).toBe(200);
        const doc = (await res.json()) as Record<string, unknown>;
        expect(doc['client_id']).toBe(url);
        expect(doc['token_endpoint_auth_method']).toBe('private_key_jwt');
        expect((doc['jwks'] as { keys: unknown[] }).keys).toHaveLength(1);
    });

    it('404s an unknown demo client', async () => {
        expect((await fetch(`${baseUrl}/demo/clients/nope`)).status).toBe(404);
    });

    it('rejects an unknown scenario id', async () => {
        const res = await fetch(`${baseUrl}/demo/run/../../etc/passwd`, { method: 'POST' });
        expect([400, 404]).toContain(res.status);
    });

    it('still guards /mcp on the demo deployment', async () => {
        const res = await fetch(`${baseUrl}/mcp`, {
            method: 'POST',
            headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
            body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }),
        });
        expect(res.status).toBe(401);
        expect(res.headers.get('www-authenticate')).toMatch(/resource_metadata=/);
    });

    describe('scenarios produce their documented outcome', () => {
        for (const meta of SCENARIOS) {
            it(`${meta.id} -> ${meta.expectSuccess ? 'succeeds' : 'is rejected'}`, async () => {
                const res = await fetch(`${baseUrl}/demo/run/${meta.id}`, { method: 'POST' });
                expect(res.status).toBe(200);
                const result = (await res.json()) as { succeeded: boolean; transcript: unknown[] };
                expect(result.succeeded).toBe(meta.expectSuccess);
                expect(result.transcript.length).toBeGreaterThan(0);
            });
        }
    });
});
