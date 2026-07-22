import express from 'express';
import rateLimit from 'express-rate-limit';
import { createResourceServerApp } from '../app.js';
import { JwtAccessTokenVerifier } from '../auth/verifiers.js';
import { createMockAuthServer } from '../mock-as/app.js';
import { canonicalResourceUrl, type AuthServerConfig, type ResourceServerConfig } from '../config.js';
import { createDemoClients } from './clients.js';
import { createDemoRouter } from './router.js';

/**
 * The public demo: authorization server, MCP resource server and demo UI in a
 * single process behind one origin.
 *
 * Deliberately one service rather than three. The demo runs a full flow on every
 * button press, and splitting it across hosts would add cross-origin failures
 * and cold-start latency to a page whose entire job is to be legible.
 *
 * This is NOT how you would deploy the template for real — an authorization
 * server sharing an origin with the resource it protects is a demo convenience.
 * The README explains the production shape.
 */
export interface DemoServerOptions {
    /** Public origin this deployment is reachable at, e.g. https://mcp-auth.coreframe.dev */
    publicUrl: string;
    port: number;
    /** Loopback http:// origins are only permitted for local development. */
    allowInsecure: boolean;
    /**
     * Address this process can reach itself on. Defaults to loopback on `port`.
     *
     * The demo talks to its own token and MCP endpoints, and the authorization
     * server fetches the client metadata documents this same process serves.
     * Inside a container the public origin generally does not resolve, and
     * depending on hairpin routing out to the internet and back is slow and
     * often blocked — so transport goes over loopback while every identity
     * (issuer, resource, client_id) stays public.
     */
    internalUrl?: string;
}

export async function createDemoServer(options: DemoServerOptions) {
    const baseUrl = options.publicUrl.replace(/\/+$/, '');
    const internalUrl = (options.internalUrl ?? `http://127.0.0.1:${options.port}`).replace(/\/+$/, '');
    const resourceUrl = canonicalResourceUrl(`${baseUrl}/mcp`);

    const registry = await createDemoClients(baseUrl);

    const app = express();
    app.disable('x-powered-by');
    // Railway and Render terminate TLS at a proxy. Without this, express-rate-limit
    // sees every request as coming from the proxy and throttles all visitors as one.
    app.set('trust proxy', 1);

    // Blanket ceiling. The per-scenario limiter in the demo router is tighter;
    // this exists so the token and MCP endpoints are not open to unlimited use
    // by anything that finds them.
    app.use(
        rateLimit({
            windowMs: 60_000,
            limit: 240,
            standardHeaders: 'draft-7',
            legacyHeaders: false,
        }),
    );

    const asConfig: AuthServerConfig = {
        port: options.port,
        issuerUrl: baseUrl,
        allowedResources: [resourceUrl],
        cimdAllowInsecure: options.allowInsecure,
        cimdCacheTtlSeconds: 300,
    };
    const as = await createMockAuthServer(asConfig, {
        // The whole reason this deployment is safe to expose.
        cimdAllowlist: registry.isAllowed,
        // Fetch our own published documents over loopback rather than round
        // -tripping through the public origin. Scoped to allowlisted ids only.
        cimdInternalRewrite: (clientId) =>
            registry.isAllowed(clientId) ? clientId.replace(baseUrl, internalUrl) : null,
    });

    const rsConfig: ResourceServerConfig = {
        port: options.port,
        resourceUrl,
        issuerUrl: baseUrl,
        jwksUri: `${baseUrl}/jwks.json`,
        requiredScopes: ['mcp:tools'],
        authMode: 'jwt',
        staticToken: undefined,
        cimdAllowInsecure: options.allowInsecure,
        cimdCacheTtlSeconds: 300,
    };
    // The advertised jwks_uri in rsConfig stays public, because that is what
    // external clients must be told. The verifier, however, has to fetch the key
    // set from inside this container, where the public origin does not resolve.
    const verifier = new JwtAccessTokenVerifier({
        issuer: baseUrl,
        resource: resourceUrl,
        jwksUri: `${internalUrl}/jwks.json`,
        requiredScopes: rsConfig.requiredScopes,
    });
    const rs = createResourceServerApp(rsConfig, verifier);

    app.use('/demo', createDemoRouter({ registry, baseUrl, internalUrl }));
    app.use(as.app);
    app.use(rs.app);
    app.get('/', (_req, res) => res.redirect(302, '/demo/'));

    return { app, shutdown: rs.shutdown, registry, resourceUrl };
}
