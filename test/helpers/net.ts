import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { Express } from 'express';
import type { Server } from 'node:http';

/**
 * Reserves an ephemeral port and releases it.
 *
 * There is an inherent race between closing here and binding later, which is
 * acceptable only because the suite runs single-process with fileParallelism
 * disabled. Do not lift this into production code.
 */
export async function getFreePort(): Promise<number> {
    const probe = createServer();
    await new Promise<void>((resolve) => probe.listen(0, '127.0.0.1', resolve));
    const { port } = probe.address() as AddressInfo;
    await new Promise<void>((resolve) => probe.close(() => resolve()));
    return port;
}

export async function listen(app: Express, port: number): Promise<Server> {
    const server = app.listen(port, '127.0.0.1');
    await new Promise<void>((resolve, reject) => {
        server.once('listening', resolve);
        server.once('error', reject);
    });
    return server;
}

export async function close(server: Server): Promise<void> {
    await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
    });
}
