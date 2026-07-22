import { describe, expect, it } from 'vitest';
import { randomBytes } from 'node:crypto';
import {
    ClientSecretStore,
    hashClientSecret,
    loadClientSecretStore,
    MIN_SECRET_LENGTH,
    verifyClientSecret,
    WeakSecretError,
} from '../src/auth/client-secret.js';

const secret = () => randomBytes(32).toString('base64url');

describe('hashClientSecret', () => {
    it('produces a self-describing scrypt hash', async () => {
        const hash = await hashClientSecret(secret());
        const parts = hash.split('$');
        expect(parts[0]).toBe('scrypt');
        expect(Number(parts[1])).toBeGreaterThan(0); // N
        expect(parts).toHaveLength(6);
    });

    it('never contains the secret', async () => {
        const s = secret();
        const hash = await hashClientSecret(s);
        expect(hash).not.toContain(s);
    });

    it('salts, so the same secret hashes differently every time', async () => {
        const s = secret();
        expect(await hashClientSecret(s)).not.toBe(await hashClientSecret(s));
    });

    it('refuses a weak secret', async () => {
        await expect(hashClientSecret('short')).rejects.toThrow(WeakSecretError);
        await expect(hashClientSecret('a'.repeat(MIN_SECRET_LENGTH - 1))).rejects.toThrow(/at least/);
    });
});

describe('verifyClientSecret', () => {
    it('accepts the correct secret', async () => {
        const s = secret();
        expect(await verifyClientSecret(s, await hashClientSecret(s))).toBe(true);
    });

    it('rejects an incorrect secret', async () => {
        expect(await verifyClientSecret(secret(), await hashClientSecret(secret()))).toBe(false);
    });

    it('rejects a secret differing by one character without throwing', async () => {
        // The comparison is over fixed-width derived keys, so differing input
        // lengths never reach timingSafeEqual — which would throw on them.
        const s = secret();
        const hash = await hashClientSecret(s);
        expect(await verifyClientSecret(`${s}x`, hash)).toBe(false);
        expect(await verifyClientSecret(s.slice(0, -1), hash)).toBe(false);
    });

    it('rejects a wildly different length without throwing', async () => {
        const hash = await hashClientSecret(secret());
        await expect(verifyClientSecret('a', hash)).resolves.toBe(false);
        await expect(verifyClientSecret('z'.repeat(5000), hash)).resolves.toBe(false);
    });

    it('rejects a malformed stored hash rather than crashing', async () => {
        expect(await verifyClientSecret('anything', 'not-a-hash')).toBe(false);
        expect(await verifyClientSecret('anything', 'scrypt$1$2$3')).toBe(false);
        expect(await verifyClientSecret('anything', '')).toBe(false);
    });
});

describe('ClientSecretStore', () => {
    it('verifies a registered client', async () => {
        const s = secret();
        const store = new ClientSecretStore([
            { clientId: 'https://a.example/client', hash: await hashClientSecret(s) },
        ]);
        expect(await store.verify('https://a.example/client', s)).toBe(true);
        expect(await store.verify('https://a.example/client', secret())) .toBe(false);
    });

    it('returns false for an unknown client', async () => {
        const store = new ClientSecretStore([]);
        expect(await store.verify('https://nope.example/client', secret())).toBe(false);
    });

    it('performs comparable work for unknown and known clients', async () => {
        // Guards the decoy path: if an unknown client short-circuited, the token
        // endpoint would become an oracle for which client_ids are registered.
        // Timing assertions are inherently noisy, so this checks the ratio is
        // within an order of magnitude rather than pinning a duration.
        const s = secret();
        const store = new ClientSecretStore([
            { clientId: 'https://a.example/client', hash: await hashClientSecret(s) },
        ]);

        const time = async (fn: () => Promise<unknown>): Promise<number> => {
            const start = performance.now();
            for (let i = 0; i < 5; i++) await fn();
            return performance.now() - start;
        };

        const known = await time(() => store.verify('https://a.example/client', secret()));
        const unknown = await time(() => store.verify('https://unknown.example/client', secret()));

        const ratio = Math.max(known, unknown) / Math.max(1, Math.min(known, unknown));
        expect(ratio).toBeLessThan(10);
    });
});

describe('loadClientSecretStore', () => {
    it('returns an empty store when unset', () => {
        expect(loadClientSecretStore(undefined).size).toBe(0);
        expect(loadClientSecretStore('').size).toBe(0);
    });

    it('loads hashes', async () => {
        const hash = await hashClientSecret(secret());
        const store = loadClientSecretStore(JSON.stringify({ 'https://a.example/client': hash }));
        expect(store.size).toBe(1);
        expect(store.has('https://a.example/client')).toBe(true);
    });

    it('rejects a plaintext secret, naming the client but not the value', async () => {
        // Storing a live secret in the environment puts it in crash dumps and
        // `docker inspect`. Fail loudly rather than accept it.
        expect(() => loadClientSecretStore(JSON.stringify({ 'https://a.example/client': 'hunter2hunter2hunter2' })))
            .toThrow(/not a scrypt hash/);
        expect(() => loadClientSecretStore(JSON.stringify({ 'https://a.example/client': 'hunter2hunter2hunter2' })))
            .not.toThrow(/hunter2/);
    });

    it('rejects malformed JSON and non-objects', () => {
        expect(() => loadClientSecretStore('{oops')).toThrow(/valid JSON/);
        expect(() => loadClientSecretStore('[]')).toThrow(/JSON object/);
        expect(() => loadClientSecretStore('"a string"')).toThrow(/JSON object/);
    });
});
