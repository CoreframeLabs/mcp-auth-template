import { randomUUID } from 'node:crypto';
import { exportJWK, generateKeyPair, type JWK, type KeyObject } from 'jose';

/**
 * Demo client identities, hosted by this server.
 *
 * A visitor cannot complete the real CIMD flow without publishing a metadata
 * document at a public HTTPS URL of their own, which is a bar essentially
 * nobody clears for a demo. So the demo server publishes a small fixed set of
 * client identities under its own origin and signs assertions on their behalf.
 *
 * Crucially this keeps the AS's URL dereferencing confined to a known allowlist
 * on our own domain. A publicly reachable CIMD authorization server that will
 * fetch any URL it is handed is an unauthenticated request amplifier and a
 * coarse host prober — see SECURITY.md. Restricting resolution to these
 * identities removes that exposure while still exercising the real code path
 * over real HTTP.
 */
export interface DemoClient {
    id: string;
    clientId: string;
    label: string;
    scope: string;
    privateKey: KeyObject | CryptoKey;
    publicJwk: JWK;
    /** A key NOT published in the metadata document, for the tampering demos. */
    impostorPrivateKey: KeyObject | CryptoKey;
}

export interface DemoClientRegistry {
    byId: Map<string, DemoClient>;
    /** True when this exact client_id URL is one we published. */
    isAllowed: (clientId: string) => boolean;
    allowedIds: string[];
}

const DEFINITIONS = [
    { id: 'well-behaved', label: 'Well-behaved client', scope: 'mcp:tools' },
    { id: 'read-only', label: 'Read-only client (lacks mcp:tools)', scope: 'mcp:read' },
] as const;

export async function createDemoClients(publicBaseUrl: string): Promise<DemoClientRegistry> {
    const base = publicBaseUrl.replace(/\/+$/, '');
    const byId = new Map<string, DemoClient>();

    for (const def of DEFINITIONS) {
        const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
        const impostor = await generateKeyPair('ES256', { extractable: true });
        const publicJwk = await exportJWK(publicKey);
        publicJwk.kid = randomUUID();
        publicJwk.alg = 'ES256';
        publicJwk.use = 'sig';

        byId.set(def.id, {
            id: def.id,
            clientId: `${base}/demo/clients/${def.id}`,
            label: def.label,
            scope: def.scope,
            privateKey,
            publicJwk,
            impostorPrivateKey: impostor.privateKey,
        });
    }

    const allowed = new Set([...byId.values()].map((c) => c.clientId));
    return {
        byId,
        allowedIds: [...allowed],
        isAllowed: (clientId: string) => allowed.has(clientId),
    };
}

/** The Client ID Metadata Document served at a demo client's client_id URL. */
export function metadataDocument(client: DemoClient): Record<string, unknown> {
    return {
        client_id: client.clientId,
        client_name: `Coreframe Demo — ${client.label}`,
        token_endpoint_auth_method: 'private_key_jwt',
        grant_types: ['client_credentials'],
        scope: client.scope,
        jwks: { keys: [client.publicJwk] },
    };
}
