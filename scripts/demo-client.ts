/**
 * End-to-end demo client.
 *
 * Walks the entire authentication path a real MCP client would take, printing
 * each step, so the flow can be inspected by hand rather than only through the
 * test suite:
 *
 *   1. publish a Client ID Metadata Document over HTTP (this is the client_id)
 *   2. sign a private_key_jwt client assertion with the matching private key
 *   3. exchange it at the authorization server for a resource-scoped token
 *   4. call the MCP server over Streamable HTTP with that token
 *   5. prove an invalid token is rejected
 *
 * Requires the authorization server to run with CIMD_ALLOW_INSECURE=true,
 * because a loopback http:// client_id is refused by the SSRF guard otherwise.
 *
 * Usage:  npm run demo
 */
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { randomUUID } from 'node:crypto';
import { exportJWK, generateKeyPair, SignJWT, type JWK } from 'jose';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

const AS_URL = process.env['AS_URL'] ?? 'http://localhost:4000';
const MCP_URL = process.env['MCP_URL'] ?? 'http://localhost:3000/mcp';
const CLIENT_PORT = Number(process.env['DEMO_CLIENT_PORT'] ?? 4100);
const CLIENT_ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

const step = (n: number, msg: string) => console.log(`\n\x1b[36m[${n}]\x1b[0m ${msg}`);
const ok = (msg: string) => console.log(`    \x1b[32m✓\x1b[0m ${msg}`);
const info = (msg: string) => console.log(`      ${msg}`);

async function main(): Promise<void> {
    // ---- 1. Become a client with a published metadata document ----------------
    step(1, 'Publishing a Client ID Metadata Document');
    const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
    const publicJwk: JWK = await exportJWK(publicKey);
    publicJwk.kid = randomUUID();
    publicJwk.alg = 'ES256';
    publicJwk.use = 'sig';

    let clientId = '';
    const docServer = createServer((_req, res) => {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(
            JSON.stringify({
                client_id: clientId,
                client_name: 'Coreframe Demo Client',
                token_endpoint_auth_method: 'private_key_jwt',
                grant_types: ['client_credentials'],
                scope: 'mcp:tools',
                jwks: { keys: [publicJwk] },
            }),
        );
    });
    await new Promise<void>((resolve) => docServer.listen(CLIENT_PORT, '127.0.0.1', resolve));
    clientId = `http://127.0.0.1:${(docServer.address() as AddressInfo).port}/`;
    ok(`client_id = ${clientId}`);
    info('The client_id IS the URL. The AS will fetch it to learn our public key.');

    try {
        // ---- 2. Sign a client assertion --------------------------------------
        step(2, 'Signing a private_key_jwt client assertion');
        const assertion = await new SignJWT({})
            .setProtectedHeader({ alg: 'ES256', kid: publicJwk.kid })
            .setIssuer(clientId)
            .setSubject(clientId)
            .setAudience(`${AS_URL}/token`)
            .setIssuedAt()
            .setExpirationTime('60s')
            .setJti(randomUUID())
            .sign(privateKey);
        ok('assertion signed');
        info(`aud = ${AS_URL}/token  (binds it to this AS only)`);
        info('jti is single-use — replaying this assertion will be rejected.');

        // ---- 3. Exchange it for an access token -------------------------------
        step(3, `Exchanging it at ${AS_URL}/token`);
        const tokenRes = await fetch(`${AS_URL}/token`, {
            method: 'POST',
            headers: { 'content-type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                grant_type: 'client_credentials',
                client_assertion_type: CLIENT_ASSERTION_TYPE,
                client_assertion: assertion,
                resource: MCP_URL,
                scope: 'mcp:tools',
            }),
        });
        const tokenBody = (await tokenRes.json()) as Record<string, string>;
        if (!tokenRes.ok) {
            console.error(`\n\x1b[31m✗ token request failed (${tokenRes.status})\x1b[0m`, tokenBody);
            console.error('\nIs the AS running with CIMD_ALLOW_INSECURE=true?');
            process.exitCode = 1;
            return;
        }
        const accessToken = tokenBody['access_token']!;
        ok(`access token issued, scope="${tokenBody['scope']}", expires_in=${tokenBody['expires_in']}s`);
        const claims = JSON.parse(Buffer.from(accessToken.split('.')[1]!, 'base64url').toString());
        info(`aud = ${claims.aud}  (usable ONLY against this resource)`);
        info(`sub = ${claims.sub}`);

        // ---- 4. Call the MCP server ------------------------------------------
        step(4, `Calling the MCP server at ${MCP_URL}`);
        const transport = new StreamableHTTPClientTransport(new URL(MCP_URL), {
            requestInit: { headers: { authorization: `Bearer ${accessToken}` } },
        });
        const client = new Client({ name: 'coreframe-demo-client', version: '1.0.0' });
        await client.connect(transport);
        ok(`initialized, session id = ${transport.sessionId}`);

        const { tools } = await client.listTools();
        ok(`tools/list -> ${tools.map((t) => t.name).join(', ')}`);

        const who = (await client.callTool({ name: 'whoami', arguments: {} })) as {
            content: { text: string }[];
        };
        ok('whoami ->');
        for (const line of who.content[0]!.text.split('\n')) info(line);

        const echo = (await client.callTool({
            name: 'echo',
            arguments: { message: 'hello from the demo client' },
        })) as { content: { text: string }[] };
        ok(`echo -> "${echo.content[0]!.text}"`);
        await client.close();

        // ---- 5. Prove a bad token is refused ---------------------------------
        step(5, 'Confirming an invalid token is rejected');
        const bad = await fetch(MCP_URL, {
            method: 'POST',
            headers: {
                'content-type': 'application/json',
                accept: 'application/json, text/event-stream',
                authorization: 'Bearer definitely-not-a-valid-token',
            },
            body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }),
        });
        ok(`invalid token -> HTTP ${bad.status} (expected 401)`);
        info(`WWW-Authenticate: ${bad.headers.get('www-authenticate')}`);

        console.log('\n\x1b[32mDemo complete.\x1b[0m\n');
    } finally {
        await new Promise<void>((resolve) => docServer.close(() => resolve()));
    }
}

main().catch((err) => {
    console.error('\n\x1b[31mDemo failed:\x1b[0m', err instanceof Error ? err.message : err);
    console.error('\nAre both servers running?  npm run dev:as   and   npm run dev');
    process.exit(1);
});
