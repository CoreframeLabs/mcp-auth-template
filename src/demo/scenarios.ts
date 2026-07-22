import { randomUUID } from 'node:crypto';
import { SignJWT } from 'jose';
import type { DemoClient, DemoClientRegistry } from './clients.js';

export const CLIENT_ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

export type ScenarioId =
    | 'happy-path'
    | 'wrong-key'
    | 'wrong-audience'
    | 'expired-assertion'
    | 'replayed-assertion'
    | 'insufficient-scope'
    | 'tampered-token'
    | 'no-token';

export interface ScenarioMeta {
    id: ScenarioId;
    title: string;
    /** What the visitor should expect, stated before the run. */
    expectation: string;
    /** Why this defence exists at all. */
    rationale: string;
    expectSuccess: boolean;
}

export const SCENARIOS: ScenarioMeta[] = [
    {
        id: 'happy-path',
        title: 'Valid client, correct everything',
        expectation: 'Token issued, MCP tools callable.',
        rationale: 'The baseline. Every rejection below is a single deviation from this run.',
        expectSuccess: true,
    },
    {
        id: 'wrong-key',
        title: 'Assertion signed with an unpublished key',
        expectation: 'Rejected at the token endpoint — 401 invalid_client.',
        rationale:
            'Possession of the private key matching the published JWKS is the entire proof of identity. An attacker who knows a client_id but not its key gets nothing.',
        expectSuccess: false,
    },
    {
        id: 'wrong-audience',
        title: 'Assertion addressed to a different token endpoint',
        expectation: 'Rejected at the token endpoint — 401 invalid_client.',
        rationale:
            'Without the audience check, an assertion captured by any other service could be replayed here to impersonate the client.',
        expectSuccess: false,
    },
    {
        id: 'expired-assertion',
        title: 'Assertion that expired ten minutes ago',
        expectation: 'Rejected at the token endpoint — 401 invalid_client.',
        rationale: 'Bounds the window in which a leaked assertion is worth anything.',
        expectSuccess: false,
    },
    {
        id: 'replayed-assertion',
        title: 'The same assertion presented twice',
        expectation: 'First exchange succeeds, second is rejected.',
        rationale:
            'Client assertions are single-use. The jti is recorded on first use, so capturing one in flight buys an attacker nothing after it has been spent.',
        expectSuccess: false,
    },
    {
        id: 'insufficient-scope',
        title: 'Valid token, but missing the mcp:tools scope',
        expectation: 'Token issued, then the MCP server returns 403.',
        rationale:
            'Authentication and authorisation are separate. Being a known client does not imply permission to call tools.',
        expectSuccess: false,
    },
    {
        id: 'tampered-token',
        title: 'A valid token with its payload edited',
        expectation: 'Rejected by the MCP server — 401 invalid_token.',
        rationale:
            'The signature covers the payload. Editing a single byte of the claims invalidates it, so scopes cannot be self-granted.',
        expectSuccess: false,
    },
    {
        id: 'no-token',
        title: 'No Authorization header at all',
        expectation: '401 with a WWW-Authenticate pointing at the metadata document.',
        rationale:
            'This is how a compliant MCP client discovers where to obtain a token. The 401 is a feature, not a failure.',
        expectSuccess: false,
    },
];

export interface TranscriptEntry {
    step: string;
    detail?: string;
    request?: { method: string; url: string; body?: string };
    response?: { status: number; headers?: Record<string, string>; body?: string };
    outcome: 'ok' | 'rejected' | 'info';
}

export interface ScenarioResult {
    scenario: ScenarioId;
    transcript: TranscriptEntry[];
    succeeded: boolean;
    summary: string;
}

function truncate(text: string, max = 1400): string {
    return text.length > max ? `${text.slice(0, max)}\n… (truncated)` : text;
}

interface Ctx {
    /** Public origin. Used for identity values: issuer, resource, client_id. */
    baseUrl: string;
    /** Loopback address. Used for the HTTP requests this runner actually makes. */
    internalUrl: string;
    registry: DemoClientRegistry;
}

async function buildAssertion(
    client: DemoClient,
    tokenEndpoint: string,
    opts: { useImpostorKey?: boolean; audience?: string; expiresInSeconds?: number; jti?: string } = {},
): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    const expiresIn = opts.expiresInSeconds ?? 60;
    return new SignJWT({})
        .setProtectedHeader({ alg: 'ES256', kid: client.publicJwk.kid })
        .setIssuer(client.clientId)
        .setSubject(client.clientId)
        .setAudience(opts.audience ?? tokenEndpoint)
        .setIssuedAt(now)
        .setExpirationTime(now + expiresIn)
        .setJti(opts.jti ?? randomUUID())
        .sign(opts.useImpostorKey ? client.impostorPrivateKey : client.privateKey);
}

async function exchange(
    ctx: Ctx,
    assertion: string,
    resource: string,
    scope: string,
): Promise<{ status: number; body: string; json: Record<string, string> }> {
    const res = await fetch(`${ctx.internalUrl}/token`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
            grant_type: 'client_credentials',
            client_assertion_type: CLIENT_ASSERTION_TYPE,
            client_assertion: assertion,
            resource,
            scope,
        }),
    });
    const body = await res.text();
    let json: Record<string, string> = {};
    try {
        json = JSON.parse(body);
    } catch {
        /* non-JSON error body; leave empty */
    }
    return { status: res.status, body, json };
}

async function callMcp(
    ctx: Ctx,
    token: string | null,
): Promise<{ status: number; body: string; headers: Record<string, string> }> {
    const res = await fetch(`${ctx.internalUrl}/mcp`, {
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
                clientInfo: { name: 'coreframe-demo', version: '1.0.0' },
            },
        }),
    });
    const body = await res.text();
    const headers: Record<string, string> = {};
    for (const key of ['www-authenticate', 'mcp-session-id', 'content-type']) {
        const value = res.headers.get(key);
        if (value) headers[key] = value;
    }
    return { status: res.status, body, headers };
}

/** Flips one character in a JWT's payload, leaving the signature untouched. */
function tamperToken(token: string): string {
    const [header, payload, signature] = token.split('.');
    const claims = JSON.parse(Buffer.from(payload!, 'base64url').toString());
    claims.scope = 'mcp:tools mcp:admin';
    const edited = Buffer.from(JSON.stringify(claims)).toString('base64url');
    return `${header}.${edited}.${signature}`;
}

export async function runScenario(ctx: Ctx, scenario: ScenarioId): Promise<ScenarioResult> {
    const transcript: TranscriptEntry[] = [];
    const tokenEndpoint = `${ctx.baseUrl}/token`;
    const resource = `${ctx.baseUrl}/mcp`;

    const client =
        scenario === 'insufficient-scope'
            ? ctx.registry.byId.get('read-only')!
            : ctx.registry.byId.get('well-behaved')!;

    transcript.push({
        step: '1. Client identity',
        detail: `client_id = ${client.clientId}\nThe client_id IS a URL. The authorization server fetches it to learn which public keys may sign this client's assertions.`,
        outcome: 'info',
    });

    if (scenario === 'no-token') {
        const mcp = await callMcp(ctx, null);
        transcript.push({
            step: '2. Call the MCP server with no credentials',
            request: { method: 'POST', url: '/mcp' },
            response: { status: mcp.status, headers: mcp.headers, body: truncate(mcp.body) },
            outcome: mcp.status === 401 ? 'rejected' : 'ok',
        });
        return {
            scenario,
            transcript,
            succeeded: false,
            summary:
                mcp.status === 401
                    ? 'Rejected with 401. The WWW-Authenticate header names the metadata document, which is how a client discovers where to get a token.'
                    : `Unexpected status ${mcp.status}.`,
        };
    }

    // ---- Build the assertion, with whatever defect this scenario calls for ----
    const defects: Record<string, string> = {
        'wrong-key': 'Signed with a key that is NOT in the published metadata document.',
        'wrong-audience': 'aud set to https://some-other-service.example/token instead of this AS.',
        'expired-assertion': 'exp set to ten minutes in the past.',
    };
    const assertion = await buildAssertion(client, tokenEndpoint, {
        useImpostorKey: scenario === 'wrong-key',
        ...(scenario === 'wrong-audience' ? { audience: 'https://some-other-service.example/token' } : {}),
        ...(scenario === 'expired-assertion' ? { expiresInSeconds: -600 } : {}),
    });
    transcript.push({
        step: '2. Sign a private_key_jwt client assertion',
        detail: defects[scenario] ?? 'Correctly signed, correctly addressed, valid for 60 seconds.',
        outcome: 'info',
    });

    // ---- Exchange it -------------------------------------------------------
    const first = await exchange(ctx, assertion, resource, client.scope);
    transcript.push({
        step: '3. Exchange the assertion for an access token',
        request: { method: 'POST', url: '/token', body: 'grant_type=client_credentials&client_assertion_type=…jwt-bearer&client_assertion=…' },
        response: { status: first.status, body: truncate(first.body) },
        outcome: first.status === 200 ? 'ok' : 'rejected',
    });

    if (first.status !== 200) {
        return {
            scenario,
            transcript,
            succeeded: false,
            summary: `Rejected at the token endpoint with ${first.status} ${first.json['error'] ?? ''}. ${first.json['error_description'] ?? ''}`,
        };
    }

    if (scenario === 'replayed-assertion') {
        const second = await exchange(ctx, assertion, resource, client.scope);
        transcript.push({
            step: '4. Present the SAME assertion a second time',
            request: { method: 'POST', url: '/token', body: 'identical body, identical jti' },
            response: { status: second.status, body: truncate(second.body) },
            outcome: second.status === 200 ? 'ok' : 'rejected',
        });
        return {
            scenario,
            transcript,
            succeeded: second.status === 200,
            summary:
                second.status === 200
                    ? 'The replay was accepted — that is a bug.'
                    : 'The replay was rejected. The jti was recorded on first use, so a captured assertion is spent.',
        };
    }

    let token = first.json['access_token']!;
    if (scenario === 'tampered-token') {
        token = tamperToken(token);
        transcript.push({
            step: '4. Edit the token payload to grant ourselves mcp:admin',
            detail: 'Claims rewritten, original signature kept.',
            outcome: 'info',
        });
    }

    const mcp = await callMcp(ctx, token);
    transcript.push({
        step: `${scenario === 'tampered-token' ? '5' : '4'}. Call the MCP server with the token`,
        request: { method: 'POST', url: '/mcp', body: 'initialize' },
        response: { status: mcp.status, headers: mcp.headers, body: truncate(mcp.body) },
        outcome: mcp.status === 200 ? 'ok' : 'rejected',
    });

    const succeeded = mcp.status === 200;

    // Summaries are selected by what actually happened, never by which scenario
    // was requested. Keying them on the scenario alone means a broken deployment
    // still reports "full flow completed" while the run plainly failed.
    const explanations: Record<string, string> = {
        'insufficient-scope':
            'The client authenticated successfully and got a token — but the token lacks mcp:tools, so the MCP server returned 403. Authentication is not authorisation.',
        'tampered-token':
            'Rejected with 401. The signature covers the payload, so edited claims invalidate the token. Scopes cannot be self-granted.',
    };

    if (scenario === 'happy-path') {
        return {
            scenario,
            transcript,
            succeeded,
            summary: succeeded
                ? 'Full flow completed. The session id in the response header identifies an authenticated MCP stream bound to this client.'
                : `Expected the full flow to succeed, but the MCP server returned ${mcp.status}. That is a fault in this deployment, not a demonstration of a defence.`,
        };
    }

    return {
        scenario,
        transcript,
        succeeded,
        summary: succeeded
            ? `Expected a rejection, but the MCP server returned 200. That is a bug.`
            : (explanations[scenario] ?? `Rejected — MCP server returned ${mcp.status}.`),
    };
}
