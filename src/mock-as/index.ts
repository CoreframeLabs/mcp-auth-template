import { loadAuthServerConfig } from '../config.js';
import { createMockAuthServer } from './app.js';

const config = loadAuthServerConfig();
const { app } = await createMockAuthServer(config);

app.listen(config.port, () => {
    console.log(`[as] MOCK authorization server listening on :${config.port}`);
    console.log(`[as] issuer:             ${config.issuerUrl}`);
    console.log(`[as] allowed resources:  ${config.allowedResources.join(', ')}`);
    console.warn('[as] This is a development mock. It has no persistence, no rate limiting, and ephemeral keys.');
});
