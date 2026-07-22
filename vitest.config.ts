import { defineConfig } from 'vitest/config';

export default defineConfig({
    test: {
        environment: 'node',
        include: ['test/**/*.test.ts'],
        // Auth tests bind ephemeral ports and share module-level caches; keep them
        // in one process per file and never interleave files that mutate env.
        fileParallelism: false,
        testTimeout: 15_000,
        restoreMocks: true,
    },
});
