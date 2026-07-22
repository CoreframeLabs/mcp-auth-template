import express, { type Express, type NextFunction, type Request, type Response } from 'express';
import { randomUUID } from 'node:crypto';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import { getOAuthProtectedResourceMetadataUrl, mcpAuthMetadataRouter } from '@modelcontextprotocol/sdk/server/auth/router.js';
import type { OAuthTokenVerifier } from '@modelcontextprotocol/sdk/server/auth/provider.js';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';
import type { ResourceServerConfig } from './config.js';
import { JwtAccessTokenVerifier, StaticTokenVerifier } from './auth/verifiers.js';
import { createMcpServer } from './mcp/server.js';

export function createVerifier(config: ResourceServerConfig): OAuthTokenVerifier {
    if (config.authMode === 'static') {
        return new StaticTokenVerifier({
            token: config.staticToken!,
            resource: config.resourceUrl,
            scopes: config.requiredScopes,
        });
    }
    return new JwtAccessTokenVerifier({
        issuer: config.issuerUrl,
        resource: config.resourceUrl,
        jwksUri: config.jwksUri!,
        requiredScopes: config.requiredScopes,
    });
}

interface Session {
    transport: StreamableHTTPServerTransport;
    /** The client the session was opened by. Sessions are not transferable. */
    ownerClientId: string;
}

function jsonRpcError(res: Response, status: number, code: number, message: string): void {
    res.status(status).json({ jsonrpc: '2.0', error: { code, message }, id: null });
}

export interface ResourceServerApp {
    app: Express;
    /** Closes every live transport. Call before process exit or between tests. */
    shutdown: () => Promise<void>;
}

export function createResourceServerApp(config: ResourceServerConfig, verifier = createVerifier(config)): ResourceServerApp {
    const app = express();
    app.disable('x-powered-by');
    app.use(express.json({ limit: '4mb' }));

    const sessions = new Map<string, Session>();
    const resourceUrl = new URL(config.resourceUrl);
    const resourceMetadataUrl = getOAuthProtectedResourceMetadataUrl(resourceUrl);

    app.get('/healthz', (_req, res) => {
        res.json({ status: 'ok', authMode: config.authMode, sessions: sessions.size });
    });

    // RFC 9728 protected resource metadata — how an MCP client discovers which
    // authorization server to go get a token from after a 401.
    //
    // Only mounted in jwt mode. Static mode has no authorization server, so
    // publishing discovery metadata (and pointing WWW-Authenticate at it) would
    // advertise an OAuth deployment that does not exist.
    if (config.authMode === 'jwt') {
        app.use(
            mcpAuthMetadataRouter({
                oauthMetadata: {
                    issuer: config.issuerUrl,
                    // Required by the OAuthMetadata type, but unused: this template
                    // covers only the server-to-server client_credentials grant, and
                    // the mock AS answers /authorize with 501 rather than pretending.
                    authorization_endpoint: `${config.issuerUrl}/authorize`,
                    token_endpoint: `${config.issuerUrl}/token`,
                    jwks_uri: config.jwksUri ?? `${config.issuerUrl}/jwks.json`,
                    grant_types_supported: ['client_credentials'],
                    token_endpoint_auth_methods_supported: ['private_key_jwt'],
                    response_types_supported: [],
                },
                resourceServerUrl: resourceUrl,
                scopesSupported: config.requiredScopes,
                resourceName: 'MCP Auth Template',
            }),
        );
    }

    const requireAuth = requireBearerAuth({
        verifier,
        requiredScopes: config.requiredScopes,
        ...(config.authMode === 'jwt' ? { resourceMetadataUrl } : {}),
    });

    const mcpPath = resourceUrl.pathname;

    /**
     * Resolves the session for a request, enforcing that the caller owns it.
     *
     * A session id is a bearer credential for an already-authenticated stream,
     * so without this check any authenticated client could attach to another
     * client's session by guessing or capturing its id.
     */
    function lookupSession(req: Request, res: Response): Session | null | undefined {
        const sessionId = req.headers['mcp-session-id'];
        if (typeof sessionId !== 'string' || sessionId.length === 0) return null;
        const session = sessions.get(sessionId);
        if (!session) {
            jsonRpcError(res, 404, -32001, 'Session not found');
            return undefined;
        }
        if (session.ownerClientId !== req.auth?.clientId) {
            // Same response as a missing session: never confirm that an id exists
            // but belongs to someone else.
            jsonRpcError(res, 404, -32001, 'Session not found');
            return undefined;
        }
        return session;
    }

    app.post(mcpPath, requireAuth, async (req, res) => {
        const existing = lookupSession(req, res);
        if (existing === undefined) return;

        if (existing) {
            await existing.transport.handleRequest(req, res, req.body);
            return;
        }

        if (!isInitializeRequest(req.body)) {
            jsonRpcError(res, 400, -32000, 'Bad Request: no valid session ID provided');
            return;
        }

        const ownerClientId = req.auth!.clientId;
        const transport = new StreamableHTTPServerTransport({
            sessionIdGenerator: () => randomUUID(),
            onsessioninitialized: (sessionId) => {
                sessions.set(sessionId, { transport, ownerClientId });
            },
        });
        transport.onclose = () => {
            if (transport.sessionId) sessions.delete(transport.sessionId);
        };

        await createMcpServer().connect(transport);
        await transport.handleRequest(req, res, req.body);
    });

    // GET opens the server->client SSE stream; DELETE terminates the session.
    const handleNonPost = async (req: Request, res: Response) => {
        const session = lookupSession(req, res);
        if (session === undefined) return;
        if (session === null) {
            jsonRpcError(res, 400, -32000, 'Bad Request: no valid session ID provided');
            return;
        }
        await session.transport.handleRequest(req, res);
    };

    app.get(mcpPath, requireAuth, handleNonPost);
    app.delete(mcpPath, requireAuth, handleNonPost);

    app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
        // Log server-side, return nothing identifying. An unhandled error here is
        // a bug, not something the caller should be able to fingerprint.
        console.error('[mcp] unhandled error:', err);
        if (res.headersSent) return;
        jsonRpcError(res, 500, -32603, 'Internal server error');
    });

    return {
        app,
        shutdown: async () => {
            await Promise.all([...sessions.values()].map((s) => s.transport.close()));
            sessions.clear();
        },
    };
}
