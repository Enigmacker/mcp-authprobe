# mcp-authprobe, built from this repository: the CLI is the entry point.
#   docker build -t mcp-authprobe .
#   docker run --rm mcp-authprobe scan https://mcp.example.com/mcp --json -
#   docker run --rm -v "$PWD/scan:/scan" -e MCP_AUTHPROBE_SECRET mcp-authprobe \
#     scan https://mcp.example.com/mcp --json /scan/report.json --sarif /scan/report.sarif
# Without arguments it runs the stdio MCP server, as earlier images did:
#   docker run -i --rm -e MCP_AUTHPROBE_SECRET mcp-authprobe
# Secrets go through MCP_AUTHPROBE_SECRET or mounted files (--secret-file,
# --bearer-file, --access-token-file, --credentials-file); see the README.
FROM node:24-slim AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.json tsconfig.build.json ./
COPY src ./src
RUN npm ci --ignore-scripts && npm run build && npm prune --omit=dev

FROM node:24-slim
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build /app/package.json ./
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY schema ./schema
COPY LICENSE ./
USER node
ENTRYPOINT ["node", "/app/dist/cli.js"]
CMD ["mcp"]
