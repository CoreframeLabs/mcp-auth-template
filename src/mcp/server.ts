import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

export const SERVER_INFO = { name: 'mcp-auth-template', version: '0.1.0' } as const;

/**
 * Builds the MCP server surface.
 *
 * A fresh instance is created per transport/session rather than shared, so one
 * client's subscriptions and progress state can never bleed into another's.
 *
 * The tools here are deliberately trivial — this template's subject is the
 * transport and the auth boundary, and `whoami` exists specifically to prove
 * the verified identity reaches tool code.
 */
export function createMcpServer(): McpServer {
    const server = new McpServer(SERVER_INFO, {
        capabilities: { tools: {}, logging: {} },
        instructions: 'Reference MCP server demonstrating OAuth 2.1 + CIMD authentication over Streamable HTTP.',
    });

    server.registerTool(
        'whoami',
        {
            title: 'Who am I',
            description: 'Returns the authenticated client identity carried by the access token.',
            inputSchema: {},
        },
        async (_args, extra) => {
            const auth = extra.authInfo;
            if (!auth) {
                // Unreachable when mounted behind requireBearerAuth; treated as a
                // hard failure rather than a silent anonymous response so that a
                // future refactor that unmounts the middleware fails loudly.
                throw new Error('no authenticated identity on request');
            }
            return {
                content: [
                    {
                        type: 'text',
                        text: JSON.stringify(
                            {
                                clientId: auth.clientId,
                                scopes: auth.scopes,
                                resource: auth.resource?.toString(),
                                expiresAt: auth.expiresAt ?? null,
                            },
                            null,
                            2,
                        ),
                    },
                ],
            };
        },
    );

    server.registerTool(
        'echo',
        {
            title: 'Echo',
            description: 'Echoes a message back. Useful for verifying end-to-end transport wiring.',
            inputSchema: { message: z.string().min(1).max(4096).describe('Text to echo back') },
        },
        async ({ message }) => ({
            content: [{ type: 'text', text: message }],
        }),
    );

    return server;
}
