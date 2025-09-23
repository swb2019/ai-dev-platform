# syntax=docker/dockerfile:1.5

FROM node:20-alpine AS base
ENV PNPM_HOME=/pnpm
ENV PATH=$PNPM_HOME:$PATH
RUN corepack enable && apk add --no-cache libc6-compat
WORKDIR /app

FROM base AS deps
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml turbo.json ./
COPY packages ./packages
COPY apps/web/package.json ./apps/web/package.json
RUN pnpm install --filter @ai-dev-platform/web... --frozen-lockfile

FROM deps AS build
COPY . .
RUN pnpm turbo run build --filter @ai-dev-platform/web...
RUN node -e "const fs=require('fs');const path=require('path');const pnpmDir='node_modules/.pnpm';const entries=fs.existsSync(pnpmDir)?fs.readdirSync(pnpmDir):[];const crossEntry=entries.find((name)=>name.startsWith('cross-spawn@'));const nextEntry=entries.find((name)=>name.startsWith('next@'));if(!crossEntry||!nextEntry){process.exit(0);}const crossDir=path.join(pnpmDir,crossEntry,'node_modules','cross-spawn');const nextCompiled=path.join(pnpmDir,nextEntry,'node_modules','next','dist','compiled','cross-spawn');if(!fs.existsSync(crossDir)){process.exit(0);}if(fs.existsSync(nextCompiled)){fs.rmSync(nextCompiled,{recursive:true,force:true});}fs.mkdirSync(nextCompiled,{recursive:true});fs.cpSync(crossDir,nextCompiled,{recursive:true});const sourcePkg=JSON.parse(fs.readFileSync(path.join(crossDir,'package.json'),'utf8'));const targetPkgPath=path.join(nextCompiled,'package.json');let targetPkg={};if(fs.existsSync(targetPkgPath)){try{targetPkg=JSON.parse(fs.readFileSync(targetPkgPath,'utf8'));}catch(e){targetPkg={};}}targetPkg.version=sourcePkg.version;fs.writeFileSync(targetPkgPath,JSON.stringify(targetPkg,null,2));"
RUN node -e "const fs=require('fs');const path='./apps/web/.next/standalone/apps/web/package.json';const data=JSON.parse(fs.readFileSync(path,'utf8'));if(data.devDependencies){delete data.devDependencies;}fs.writeFileSync(path, JSON.stringify(data, null, 2));"
RUN node -e "const fs=require('fs');const path='./apps/web/.next/standalone/package.json';if(!fs.existsSync(path)){process.exit(0);}const data=JSON.parse(fs.readFileSync(path,'utf8'));delete data.devDependencies;delete data['lint-staged'];delete data.pnpm;fs.writeFileSync(path, JSON.stringify(data, null, 2));"

FROM node:20-alpine AS runner
ENV NODE_ENV=production
ENV PNPM_HOME=/pnpm
ENV PATH=$PNPM_HOME:$PATH
RUN corepack enable && apk add --no-cache libc6-compat \
  && addgroup -g 1001 nodejs \
  && adduser -S nextjs -G nodejs -u 1001
WORKDIR /app

COPY --from=build /app/apps/web/.next/standalone ./
COPY --from=build /app/apps/web/.next/static ./apps/web/.next/static
COPY --from=build /app/apps/web/public ./apps/web/public

USER nextjs
EXPOSE 3000
ENV PORT=3000
CMD ["node", "apps/web/server.js"]
