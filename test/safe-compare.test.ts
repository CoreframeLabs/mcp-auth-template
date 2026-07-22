import { describe, expect, it } from 'vitest';
import { timingSafeEqualString } from '../src/util/safe-compare.js';

describe('timingSafeEqualString', () => {
    it('accepts identical strings', () => {
        expect(timingSafeEqualString('correct-horse-battery-staple', 'correct-horse-battery-staple')).toBe(true);
    });

    it('rejects strings differing in a single character', () => {
        expect(timingSafeEqualString('token-aaaaaaaaaaaaaaaaaaaa', 'token-aaaaaaaaaaaaaaaaaaab')).toBe(false);
    });

    it('rejects strings of different lengths without throwing', () => {
        // crypto.timingSafeEqual throws on length mismatch; the HMAC step is what
        // makes this safe. A regression here surfaces as an exception, not a
        // wrong answer, so assert on the return value explicitly.
        expect(() => timingSafeEqualString('short', 'considerably-longer-value')).not.toThrow();
        expect(timingSafeEqualString('short', 'considerably-longer-value')).toBe(false);
    });

    it('handles empty strings', () => {
        expect(timingSafeEqualString('', '')).toBe(true);
        expect(timingSafeEqualString('', 'x')).toBe(false);
    });

    it('compares by bytes, not by unicode normalization form', () => {
        // "é" as one code point vs "e" + combining accent. They render alike but
        // are different secrets, and must not be treated as equal.
        expect(timingSafeEqualString('café', 'café')).toBe(false);
    });

    it('is not fooled by a prefix', () => {
        expect(timingSafeEqualString('secret', 'secret-extra')).toBe(false);
        expect(timingSafeEqualString('secret-extra', 'secret')).toBe(false);
    });
});
