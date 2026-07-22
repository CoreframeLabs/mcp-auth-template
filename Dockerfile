# syntax=docker/dockerfile:1

# ---- build ----------------------------------------------------------------
FROM node:22-alpine AS build
WORKDIR /app

# Copy manifests first so dependency installation is cached independently of
# source changes.
COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
RUN npm run build

# Drop dev dependencies from the tree we are about to copy forward.
RUN npm prune --omit=dev

# ---- runtime --------------------------------------------------------------
FROM node:22-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production

# Run unprivileged. The node image ships a `node` user for exactly this.
USER node

COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/dist ./dist
COPY --from=build --chown=node:node /app/package.json ./package.json

# Railway and Render inject PORT; this default is only for local `docker run`.
ENV PORT=3000
EXPOSE 3000

# No shell form: keeps node as PID 1 so SIGTERM reaches it and the graceful
# shutdown handler actually runs on deploy and scale-down.
CMD ["node", "dist/demo/index.js"]
