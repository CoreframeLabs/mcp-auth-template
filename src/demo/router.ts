import express, { type Router } from 'express';
import rateLimit from 'express-rate-limit';
import { metadataDocument, type DemoClientRegistry } from './clients.js';
import { runScenario, SCENARIOS, type ScenarioId } from './scenarios.js';
import { renderDemoPage } from './page.js';

const VALID_SCENARIOS = new Set<string>(SCENARIOS.map((s) => s.id));

export function createDemoRouter(options: {
    registry: DemoClientRegistry;
    /** Public origin — used for identity values shown to the visitor. */
    baseUrl: string;
    /** Loopback address — used for the HTTP calls the scenarios actually make. */
    internalUrl: string;
}): Router {
    const router = express.Router();
    const { registry, baseUrl, internalUrl } = options;

    // Each scenario run makes the server issue several HTTP requests to itself.
    // Without a cap, one visitor holding down a button is a self-inflicted load
    // generator.
    const runLimiter = rateLimit({
        windowMs: 60_000,
        limit: 20,
        standardHeaders: 'draft-7',
        legacyHeaders: false,
        message: { error: 'rate_limited', error_description: 'Too many scenario runs. Wait a minute.' },
    });

    router.get('/', (_req, res) => {
        res.type('html').send(renderDemoPage(SCENARIOS, registry));
    });

    // The Client ID Metadata Documents themselves. This is the URL the
    // authorization server dereferences, so these must be publicly readable.
    router.get('/clients/:id', (req, res) => {
        const client = registry.byId.get(req.params.id);
        if (!client) {
            res.status(404).json({ error: 'not_found' });
            return;
        }
        res.set('cache-control', 'public, max-age=60').json(metadataDocument(client));
    });

    router.get('/scenarios', (_req, res) => {
        res.json({ scenarios: SCENARIOS });
    });

    router.post('/run/:scenario', runLimiter, async (req, res) => {
        const scenario = String(req.params.scenario ?? '');
        if (!VALID_SCENARIOS.has(scenario)) {
            res.status(400).json({ error: 'unknown_scenario' });
            return;
        }
        try {
            const result = await runScenario({ baseUrl, internalUrl, registry }, scenario as ScenarioId);
            res.json(result);
        } catch (err) {
            console.error('[demo] scenario failed:', err);
            res.status(500).json({ error: 'scenario_failed' });
        }
    });

    return router;
}
