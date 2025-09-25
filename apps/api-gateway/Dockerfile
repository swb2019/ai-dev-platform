# syntax=docker/dockerfile:1.5

FROM node:20-alpine AS base
ENV PNPM_HOME=/pnpm
ENV PATH=$PNPM_HOME:$PATH
RUN corepack enable && apk add --no-cache libc6-compat
WORKDIR /app

FROM base AS deps
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml turbo.json ./
COPY packages ./packages
COPY apps/api-gateway/package.json ./apps/api-gateway/package.json
RUN pnpm install --filter @ai-dev-platform/api-gateway... --frozen-lockfile

FROM deps AS build
COPY . .
RUN pnpm turbo run build --filter @ai-dev-platform/api-gateway...
RUN pnpm prune --prod

FROM node:20-alpine AS runner
ENV NODE_ENV=production
ENV PNPM_HOME=/pnpm
ENV PATH=$PNPM_HOME:$PATH
RUN corepack enable && apk add --no-cache libc6-compat \
  && addgroup -g 1001 nodejs \
  && adduser -S appuser -G nodejs -u 1001
WORKDIR /app

COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/pnpm-lock.yaml ./pnpm-lock.yaml
COPY --from=build /app/apps/api-gateway/package.json ./apps/api-gateway/package.json
COPY --from=build /app/apps/api-gateway/dist ./apps/api-gateway/dist

WORKDIR /app/apps/api-gateway

USER appuser
EXPOSE 4000
ENV PORT=4000
CMD ["node", "dist/index.js"]
