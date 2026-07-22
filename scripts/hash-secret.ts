/**
 * Generates a client secret and its scrypt hash.
 *
 * Only the hash is ever configured on the server (`CLIENT_SECRETS`); the secret
 * itself goes to the client and is never stored here. That way a leaked config
 * file or environment dump does not yield working credentials.
 *
 * Usage:
 *   npm run hash-secret -- <client_id>            # generate a fresh secret
 *   npm run hash-secret -- <client_id> <secret>   # hash an existing one
 */
import { randomBytes } from 'node:crypto';
import { hashClientSecret, MIN_SECRET_LENGTH, WeakSecretError } from '../src/auth/client-secret.js';

const [clientId, provided] = process.argv.slice(2);

if (!clientId) {
    console.error('Usage: npm run hash-secret -- <client_id> [secret]');
    process.exit(1);
}

const secret = provided ?? randomBytes(32).toString('base64url');

try {
    const hash = await hashClientSecret(secret);

    console.log('\nGive this secret to the client (shown once — it is not stored):\n');
    console.log(`  ${secret}\n`);
    console.log('Add this to the server\'s CLIENT_SECRETS environment variable:\n');
    console.log(`  ${JSON.stringify({ [clientId]: hash })}\n`);
    console.log('To register several clients, merge the objects:\n');
    console.log('  CLIENT_SECRETS=\'{"https://a.example/client":"scrypt$...","https://b.example/client":"scrypt$..."}\'\n');
} catch (err) {
    if (err instanceof WeakSecretError) {
        console.error(`\n${err.message}\n`);
        console.error(`Secrets must be at least ${MIN_SECRET_LENGTH} characters.`);
        process.exit(1);
    }
    throw err;
}
