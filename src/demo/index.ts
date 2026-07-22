import { createDemoServer } from './server.js';

/**
 * Entrypoint for the hosted demo. Railway/Render inject PORT.
 *
 * PUBLIC_URL must be the externally reachable origin, because it becomes the
 * OAuth issuer, the RFC 8707 resource identifier, and the client_id URLs the
 * authorization server dereferences. If it is wrong, every token fails its
 * audience check — so it is validated at boot rather than left to fail later.
 */
const port = Number(process.env['PORT'] ?? 3000);
const publicUrl = process.env['PUBLIC_URL'] ?? `http://localhost:${port}`;

let parsed: URL;
try {
    parsed = new URL(publicUrl);
} catch {
    console.error(`[demo] PUBLIC_URL is not a valid URL: ${publicUrl}`);
    process.exit(1);
}

const isLoopback = ['localhost', '127.0.0.1', '::1'].includes(parsed.hostname);
if (parsed.protocol !== 'https:' && !isLoopback) {
    console.error(`[demo] PUBLIC_URL must use https in a public deployment (got ${publicUrl}).`);
    process.exit(1);
}

const { app, shutdown, registry } = await createDemoServer({
    publicUrl,
    port,
    // Only relaxed for loopback development, never for a deployed origin.
    allowInsecure: isLoopback,
});

const server = app.listen(port, () => {
    console.log(`[demo] listening on :${port}`);
    console.log(`[demo] public url:  ${publicUrl}`);
    console.log(`[demo] demo page:   ${publicUrl}/demo/`);
    console.log(`[demo] allowlisted client ids:`);
    for (const id of registry.allowedIds) console.log(`         ${id}`);
    if (isLoopback) console.warn('[demo] loopback mode: CIMD SSRF guard relaxed for http:// client ids.');
});

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
    process.on(signal, () => {
        console.log(`[demo] ${signal} received, draining…`);
        server.close(() => void shutdown().then(() => process.exit(0)));
    });
}
