import { createDemoServer } from './server.js';
import { PublicUrlError, resolvePublicUrl } from './public-url.js';

/**
 * Entrypoint for the hosted demo. Railway/Render inject PORT.
 *
 * The public origin is resolved from PUBLIC_URL, or auto-detected from the
 * platform (RAILWAY_PUBLIC_DOMAIN / RENDER_EXTERNAL_URL) when PUBLIC_URL is
 * unset. It becomes the OAuth issuer, the RFC 8707 resource identifier, and the
 * client_id URLs, so it is resolved and validated up front — see public-url.ts
 * for why this is the deploy step people get wrong.
 */
const port = Number(process.env['PORT'] ?? 3000);

let resolved;
try {
    resolved = resolvePublicUrl(process.env, port);
} catch (err) {
    if (err instanceof PublicUrlError) {
        console.error(`[demo] ${err.message}`);
        console.error('[demo] Set PUBLIC_URL to your full https origin, e.g.');
        console.error('[demo]   PUBLIC_URL=https://your-app.up.railway.app');
        console.error('[demo] On Railway you can also just generate a domain and leave PUBLIC_URL unset.');
        process.exit(1);
    }
    throw err;
}

const { url: publicUrl, source, isLoopback, suspectedMisconfiguration } = resolved;

if (suspectedMisconfiguration) {
    // Loud, because the platform-rollback-on-crash behaviour otherwise hides it:
    // better to boot with a visible warning than to exit and be rolled back to a
    // stale instance.
    console.warn('[demo] ============================================================');
    console.warn('[demo] WARNING: falling back to a localhost public URL on what looks');
    console.warn('[demo] like a deployed host. External clients will not work.');
    console.warn('[demo] Generate a public domain, or set PUBLIC_URL explicitly.');
    console.warn('[demo] ============================================================');
}

const { app, shutdown, registry } = await createDemoServer({
    publicUrl,
    port,
    // Only relaxed for loopback development, never for a deployed origin.
    allowInsecure: isLoopback,
});

const server = app.listen(port, () => {
    console.log(`[demo] listening on :${port}`);
    console.log(`[demo] public url:  ${publicUrl}  (from ${source})`);
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
