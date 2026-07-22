import { describe, expect, it } from 'vitest';
import type { Request } from 'express';
import {
    ClientAuthError,
    CLIENT_ASSERTION_TYPE,
    parseClientAuthentication,
} from '../src/auth/client-authentication.js';

function req(body: Record<string, unknown>, headers: Record<string, string> = {}): Request {
    return { body, headers } as unknown as Request;
}

const basic = (id: string, secret: string) =>
    `Basic ${Buffer.from(`${encodeURIComponent(id)}:${encodeURIComponent(secret)}`).toString('base64')}`;

describe('parseClientAuthentication', () => {
    it('recognises private_key_jwt', () => {
        const auth = parseClientAuthentication(
            req({ client_assertion_type: CLIENT_ASSERTION_TYPE, client_assertion: 'a.b.c' }),
        );
        expect(auth).toEqual({ method: 'private_key_jwt', assertion: 'a.b.c' });
    });

    it('rejects an assertion with the wrong assertion type', () => {
        expect(() =>
            parseClientAuthentication(req({ client_assertion_type: 'nope', client_assertion: 'a.b.c' })),
        ).toThrow(/unsupported client_assertion_type/);
    });

    it('recognises client_secret_basic and url-decodes both halves', () => {
        const auth = parseClientAuthentication(req({}, { authorization: basic('https://a.example/c', 'p@ss:word') }));
        expect(auth).toEqual({
            method: 'client_secret_basic',
            clientId: 'https://a.example/c',
            secret: 'p@ss:word',
        });
    });

    it('splits Basic credentials on the FIRST colon only', () => {
        // A secret containing a colon must survive intact; splitting on the last
        // colon would silently truncate it and reject valid credentials.
        const auth = parseClientAuthentication(req({}, { authorization: basic('id', 'a:b:c') }));
        expect(auth).toMatchObject({ secret: 'a:b:c' });
    });

    it('recognises client_secret_post', () => {
        const auth = parseClientAuthentication(
            req({ client_id: 'https://a.example/c', client_secret: 'shhh' }),
        );
        expect(auth).toEqual({
            method: 'client_secret_post',
            clientId: 'https://a.example/c',
            secret: 'shhh',
        });
    });

    it('requires some form of client authentication', () => {
        expect(() => parseClientAuthentication(req({}))).toThrow(ClientAuthError);
        expect(() => parseClientAuthentication(req({}))).toThrow(/required/);
    });

    it('refuses more than one mechanism at once', () => {
        // RFC 6749 §2.3 permits exactly one. Accepting several would let a caller
        // pair a valid credential with a forged one and hope the server checks
        // the wrong one first.
        expect(() =>
            parseClientAuthentication(
                req({ client_id: 'x', client_secret: 'y' }, { authorization: basic('x', 'y') }),
            ),
        ).toThrow(/exactly one/);

        expect(() =>
            parseClientAuthentication(
                req({ client_assertion_type: CLIENT_ASSERTION_TYPE, client_assertion: 'a.b.c', client_id: 'x', client_secret: 'y' }),
            ),
        ).toThrow(/exactly one/);
    });

    it('rejects a malformed Basic header', () => {
        expect(() => parseClientAuthentication(req({}, { authorization: 'Basic notbase64!!!' }))).toThrow(
            ClientAuthError,
        );
        expect(() =>
            parseClientAuthentication(req({}, { authorization: `Basic ${Buffer.from('nocolon').toString('base64')}` })),
        ).toThrow(/malformed/);
    });

    it('rejects Basic credentials missing a component', () => {
        expect(() =>
            parseClientAuthentication(req({}, { authorization: `Basic ${Buffer.from(':secret').toString('base64')}` })),
        ).toThrow(/missing a component/);
        expect(() =>
            parseClientAuthentication(req({}, { authorization: `Basic ${Buffer.from('id:').toString('base64')}` })),
        ).toThrow(/missing a component/);
    });

    it('requires client_id alongside client_secret_post', () => {
        expect(() => parseClientAuthentication(req({ client_secret: 'shhh' }))).toThrow(/client_id is required/);
    });
});
