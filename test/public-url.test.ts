import { describe, expect, it } from 'vitest';
import { PublicUrlError, resolvePublicUrl } from '../src/demo/public-url.js';

const resolve = (env: NodeJS.ProcessEnv, port = 3000) => resolvePublicUrl(env, port);

describe('resolvePublicUrl', () => {
    it('uses an explicit https PUBLIC_URL', () => {
        const r = resolve({ PUBLIC_URL: 'https://mcp-auth.coreframe.dev' });
        expect(r.url).toBe('https://mcp-auth.coreframe.dev');
        expect(r.source).toBe('PUBLIC_URL');
        expect(r.isLoopback).toBe(false);
    });

    it('upgrades a schemeless PUBLIC_URL to https', () => {
        // The exact mistake seen in the wild: a bare Railway domain.
        const r = resolve({ PUBLIC_URL: 'mcp-auth-demo-production-d421.up.railway.app' });
        expect(r.url).toBe('https://mcp-auth-demo-production-d421.up.railway.app');
    });

    it('strips surrounding quotes and whitespace', () => {
        const r = resolve({ PUBLIC_URL: '  "https://mcp-auth.coreframe.dev"  ' });
        expect(r.url).toBe('https://mcp-auth.coreframe.dev');
    });

    it('strips a path, query and trailing slash down to the origin', () => {
        const r = resolve({ PUBLIC_URL: 'https://mcp-auth.coreframe.dev/demo/?x=1' });
        expect(r.url).toBe('https://mcp-auth.coreframe.dev');
    });

    it('auto-detects Railway when PUBLIC_URL is unset', () => {
        const r = resolve({ RAILWAY_PUBLIC_DOMAIN: 'foo.up.railway.app' });
        expect(r.url).toBe('https://foo.up.railway.app');
        expect(r.source).toBe('RAILWAY_PUBLIC_DOMAIN');
    });

    it('auto-detects Render when PUBLIC_URL is unset', () => {
        const r = resolve({ RENDER_EXTERNAL_URL: 'https://foo.onrender.com' });
        expect(r.url).toBe('https://foo.onrender.com');
        expect(r.source).toBe('RENDER_EXTERNAL_URL');
    });

    it('prefers an explicit PUBLIC_URL over platform detection', () => {
        const r = resolve({
            PUBLIC_URL: 'https://custom.example',
            RAILWAY_PUBLIC_DOMAIN: 'foo.up.railway.app',
        });
        expect(r.url).toBe('https://custom.example');
        expect(r.source).toBe('PUBLIC_URL');
    });

    it('defaults to loopback when nothing is set', () => {
        const r = resolve({}, 8080);
        expect(r.url).toBe('http://localhost:8080');
        expect(r.isLoopback).toBe(true);
        expect(r.suspectedMisconfiguration).toBe(false);
    });

    it('flags a localhost fallback on an apparently deployed host', () => {
        // The scenario this whole module exists to make visible.
        const r = resolve({ RAILWAY_ENVIRONMENT: 'production' }, 8080);
        expect(r.isLoopback).toBe(true);
        expect(r.suspectedMisconfiguration).toBe(true);
    });

    it('treats an empty RAILWAY_PUBLIC_DOMAIN as unset (the template deploy bug)', () => {
        const r = resolve({ RAILWAY_PUBLIC_DOMAIN: '', RAILWAY_ENVIRONMENT: 'production' }, 8080);
        expect(r.source).toBe('default');
        expect(r.suspectedMisconfiguration).toBe(true);
    });

    describe('rejections', () => {
        it('rejects an explicit http origin on a public host', () => {
            expect(() => resolve({ PUBLIC_URL: 'http://foo.up.railway.app' })).toThrow(PublicUrlError);
            expect(() => resolve({ PUBLIC_URL: 'http://foo.up.railway.app' })).toThrow(/must use https/);
        });

        it('permits http for loopback development', () => {
            expect(resolve({ PUBLIC_URL: 'http://localhost:3000' }).isLoopback).toBe(true);
            expect(resolve({ PUBLIC_URL: 'http://127.0.0.1:3000' }).isLoopback).toBe(true);
        });

        it('rejects a value that cannot be made into a URL on either pass', () => {
            // Spaces are invalid in an authority, so neither `raw` nor
            // `https://${raw}` parses.
            expect(() => resolve({ PUBLIC_URL: 'not a url value' })).toThrow(PublicUrlError);
        });
    });
});
