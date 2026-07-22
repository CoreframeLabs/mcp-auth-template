import type { Request } from 'express';

/**
 * Parsing of RFC 6749 client authentication from a token request.
 *
 * Kept separate from the token endpoint itself: deciding *what the client
 * claims to be* is a distinct concern from deciding whether to believe it, and
 * this half is pure and directly testable.
 */

export const CLIENT_ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

export type ClientAuthMethod = 'private_key_jwt' | 'client_secret_basic' | 'client_secret_post';

export const SUPPORTED_AUTH_METHODS: ClientAuthMethod[] = [
    'private_key_jwt',
    'client_secret_basic',
    'client_secret_post',
];

export type ClientAuthentication =
    | { method: 'private_key_jwt'; assertion: string }
    | { method: 'client_secret_basic' | 'client_secret_post'; clientId: string; secret: string };

export class ClientAuthError extends Error {
    constructor(
        message: string,
        readonly oauthError: 'invalid_client' | 'invalid_request' = 'invalid_client',
    ) {
        super(message);
        this.name = 'ClientAuthError';
    }
}

/** Decodes an `Authorization: Basic` header per RFC 6749 §2.3.1. */
function parseBasic(header: string): { clientId: string; secret: string } {
    const encoded = header.slice('basic '.length).trim();
    let decoded: string;
    try {
        decoded = Buffer.from(encoded, 'base64').toString('utf8');
    } catch {
        throw new ClientAuthError('malformed Basic authorization header');
    }
    const separator = decoded.indexOf(':');
    if (separator === -1) throw new ClientAuthError('malformed Basic authorization header');

    // RFC 6749 requires both halves be form-urlencoded before base64.
    const clientId = decodeURIComponent(decoded.slice(0, separator));
    const secret = decoded.slice(separator + 1);
    if (!clientId || !secret) throw new ClientAuthError('Basic authorization header is missing a component');
    return { clientId, secret: decodeURIComponent(secret) };
}

/**
 * Determines how the client is authenticating.
 *
 * Rejects requests that present more than one mechanism. RFC 6749 §2.3 requires
 * exactly one: accepting several would let a caller pair a valid credential of
 * one kind with a forged one of another and hope the server checks the wrong
 * one first.
 */
export function parseClientAuthentication(req: Request): ClientAuthentication {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const authorization = req.headers.authorization;

    const hasBasic = typeof authorization === 'string' && authorization.toLowerCase().startsWith('basic ');
    const hasAssertion = typeof body['client_assertion'] === 'string' && body['client_assertion'].length > 0;
    const hasPostSecret = typeof body['client_secret'] === 'string' && body['client_secret'].length > 0;

    const presented = [hasBasic, hasAssertion, hasPostSecret].filter(Boolean).length;
    if (presented === 0) {
        throw new ClientAuthError('client authentication is required');
    }
    if (presented > 1) {
        throw new ClientAuthError('exactly one client authentication mechanism may be presented', 'invalid_request');
    }

    if (hasAssertion) {
        if (body['client_assertion_type'] !== CLIENT_ASSERTION_TYPE) {
            throw new ClientAuthError('unsupported client_assertion_type');
        }
        return { method: 'private_key_jwt', assertion: body['client_assertion'] as string };
    }

    if (hasBasic) {
        const { clientId, secret } = parseBasic(authorization);
        return { method: 'client_secret_basic', clientId, secret };
    }

    const clientId = body['client_id'];
    if (typeof clientId !== 'string' || clientId.length === 0) {
        throw new ClientAuthError('client_id is required with client_secret_post');
    }
    return { method: 'client_secret_post', clientId, secret: body['client_secret'] as string };
}
