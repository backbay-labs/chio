FROM node:22-bookworm-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3
RUN npm install --global --ignore-scripts openclaw@2026.5.20
COPY chio-openclaw-kernel-0.1.0.tgz /opt/chio-package.tgz
RUN npm install --prefix /opt/chio --ignore-scripts --offline --no-audit --no-fund /opt/chio-package.tgz \
    && rm /opt/chio-package.tgz
COPY proxy.mjs /opt/chio/proxy.mjs
ENV OPENCLAW_NO_RESPAWN=1 OPENCLAW_DISABLE_BONJOUR=1 OPENCLAW_HOME=/state/home OPENCLAW_STATE_DIR=/state/openclaw OPENCLAW_CONFIG_PATH=/config/openclaw.json
USER node
WORKDIR /tmp
ENTRYPOINT ["openclaw"]
