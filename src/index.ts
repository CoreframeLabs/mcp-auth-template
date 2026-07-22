import { createResourceServerApp } from './app.js';
import { loadResourceServerConfig } from './config.js';

const config = loadResourceServerConfig();

if (config.authMode === 'static') {
    console.warn('[mcp] WARNING: MCP_AUTH_MODE=static uses a single shared secret. Never run this in production.');
}
if (config.cimdAllowInsecure) {
    console.warn('[mcp] WARNING: CIMD_ALLOW_INSECURE=true disables the SSRF guard on client_id URLs.');
}

const { app, shutdown } = createResourceServerApp(config);

const server = app.listen(config.port, () => {
    console.log(`[mcp] resource server listening on :${config.port}`);
    console.log(`[mcp] resource identifier: ${config.resourceUrl}`);
    console.log(`[mcp] trusted issuer:      ${config.issuerUrl}`);
});

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
    process.on(signal, () => {
        console.log(`[mcp] ${signal} received, draining…`);
        server.close(() => {
            void shutdown().then(() => process.exit(0));
        });
    });
}
