FROM node:22-bookworm-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3
WORKDIR /opt/resource
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --omit=dev --no-audit --no-fund
COPY audit-tool-server.mjs ./audit-tool-server.mjs
USER node
ENTRYPOINT ["node", "/opt/resource/audit-tool-server.mjs"]
