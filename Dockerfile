# mcp-authprobe as a stdio MCP server, built from this repository.
#   docker build -t mcp-authprobe .
#   docker run -i --rm mcp-authprobe
# Configuration (ownership secret, lab origins...) goes through MCP_AUTHPROBE_*
# environment variables; see the README. The CLI is available with
#   docker run --rm --entrypoint node mcp-authprobe dist/cli.js --help
FROM node:22-slim AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.json tsconfig.build.json ./
COPY src ./src
RUN npm ci --ignore-scripts && npm run build && npm prune --omit=dev

FROM node:22-slim
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build /app/package.json ./
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
USER node
ENTRYPOINT ["node", "dist/cli.js", "mcp"]
