import { z } from 'zod';

/** Parses the handful of spellings people actually put in a .env file. */
const boolish = z
    .string()
    .default('false')
    .transform((v) => v.trim().toLowerCase())
    .refine((v) => ['true', 'false', '1', '0', 'yes', 'no', ''].includes(v), {
        message: 'expected a boolean-like value (true/false/1/0/yes/no)',
    })
    .transform((v) => v === 'true' || v === '1' || v === 'yes');

const scopeList = z
    .string()
    .default('mcp:tools')
    .transform((v) => v.split(/[\s,]+/).filter(Boolean));

const httpUrl = z.string().refine(
    (v) => {
        try {
            const u = new URL(v);
            return u.protocol === 'http:' || u.protocol === 'https:';
        } catch {
            return false;
        }
    },
    { message: 'must be an absolute http(s) URL' },
);

/**
 * RFC 8707 resource identifiers are compared by exact string match, so a stray
 * fragment or trailing slash silently turns every token into an audience
 * mismatch. Normalise once, here, and use the result everywhere.
 */
export function canonicalResourceUrl(raw: string): string {
    const u = new URL(raw);
    u.hash = '';
    if (u.pathname.length > 1 && u.pathname.endsWith('/')) {
        u.pathname = u.pathname.replace(/\/+$/, '');
    }
    return u.toString();
}

const ResourceServerEnv = z
    .object({
        PORT: z.coerce.number().int().min(1).max(65535).default(3000),
        MCP_RESOURCE_URL: httpUrl,
        MCP_ISSUER_URL: httpUrl,
        MCP_JWKS_URI: httpUrl.optional(),
        MCP_REQUIRED_SCOPES: scopeList,
        MCP_AUTH_MODE: z.enum(['jwt', 'static']).default('jwt'),
        MCP_STATIC_TOKEN: z.string().optional(),
        CIMD_ALLOW_INSECURE: boolish,
        CIMD_CACHE_TTL_SECONDS: z.coerce.number().int().positive().max(86_400).default(300),
    })
    .superRefine((v, ctx) => {
        if (v.MCP_AUTH_MODE === 'static') {
            if (!v.MCP_STATIC_TOKEN) {
                ctx.addIssue({
                    code: 'custom',
                    path: ['MCP_STATIC_TOKEN'],
                    message: 'required when MCP_AUTH_MODE=static',
                });
            } else if (v.MCP_STATIC_TOKEN.length < 32) {
                ctx.addIssue({
                    code: 'custom',
                    path: ['MCP_STATIC_TOKEN'],
                    message: 'must be at least 32 characters; generate with crypto.randomBytes(32)',
                });
            }
        } else if (!v.MCP_JWKS_URI) {
            ctx.addIssue({
                code: 'custom',
                path: ['MCP_JWKS_URI'],
                message: 'required when MCP_AUTH_MODE=jwt',
            });
        }
    });

export interface ResourceServerConfig {
    port: number;
    resourceUrl: string;
    issuerUrl: string;
    jwksUri: string | undefined;
    requiredScopes: string[];
    authMode: 'jwt' | 'static';
    staticToken: string | undefined;
    cimdAllowInsecure: boolean;
    cimdCacheTtlSeconds: number;
}

export function loadResourceServerConfig(env: NodeJS.ProcessEnv = process.env): ResourceServerConfig {
    const parsed = ResourceServerEnv.safeParse(env);
    if (!parsed.success) throw new ConfigError('resource server', parsed.error);
    const v = parsed.data;
    return {
        port: v.PORT,
        resourceUrl: canonicalResourceUrl(v.MCP_RESOURCE_URL),
        issuerUrl: v.MCP_ISSUER_URL.replace(/\/+$/, ''),
        jwksUri: v.MCP_JWKS_URI,
        requiredScopes: v.MCP_REQUIRED_SCOPES,
        authMode: v.MCP_AUTH_MODE,
        staticToken: v.MCP_STATIC_TOKEN,
        cimdAllowInsecure: v.CIMD_ALLOW_INSECURE,
        cimdCacheTtlSeconds: v.CIMD_CACHE_TTL_SECONDS,
    };
}

const AuthServerEnv = z.object({
    AS_PORT: z.coerce.number().int().min(1).max(65535).default(4000),
    AS_ISSUER_URL: httpUrl,
    AS_ALLOWED_RESOURCES: z
        .string()
        .transform((v) => v.split(/[\s,]+/).filter(Boolean))
        .refine((v) => v.length > 0, { message: 'at least one resource identifier is required' }),
    CIMD_ALLOW_INSECURE: boolish,
    CIMD_CACHE_TTL_SECONDS: z.coerce.number().int().positive().max(86_400).default(300),
});

export interface AuthServerConfig {
    port: number;
    issuerUrl: string;
    allowedResources: string[];
    cimdAllowInsecure: boolean;
    cimdCacheTtlSeconds: number;
}

export function loadAuthServerConfig(env: NodeJS.ProcessEnv = process.env): AuthServerConfig {
    const parsed = AuthServerEnv.safeParse(env);
    if (!parsed.success) throw new ConfigError('authorization server', parsed.error);
    const v = parsed.data;
    return {
        port: v.AS_PORT,
        issuerUrl: v.AS_ISSUER_URL.replace(/\/+$/, ''),
        allowedResources: v.AS_ALLOWED_RESOURCES.map(canonicalResourceUrl),
        cimdAllowInsecure: v.CIMD_ALLOW_INSECURE,
        cimdCacheTtlSeconds: v.CIMD_CACHE_TTL_SECONDS,
    };
}

/**
 * Fails loudly at boot with every problem listed at once. Deliberately prints
 * only the offending variable *names* — never their values, since these are the
 * exact places secrets live.
 */
export class ConfigError extends Error {
    constructor(what: string, cause: z.ZodError) {
        const lines = cause.issues.map((i) => `  - ${i.path.join('.') || '(root)'}: ${i.message}`);
        super(`Invalid ${what} configuration:\n${lines.join('\n')}\n\nSee .env.example.`);
        this.name = 'ConfigError';
    }
}
