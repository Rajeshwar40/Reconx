# ── Stage 1: build the recon tool chain via the OS-detecting installer ──
FROM debian:bookworm-slim AS tools

RUN apt-get update && apt-get install -y --no-install-recommends sudo && rm -rf /var/lib/apt/lists/*

COPY scripts/install-tools.sh /tmp/install-tools.sh
RUN chmod +x /tmp/install-tools.sh && /tmp/install-tools.sh

# ── Stage 2: runtime image ───────────────────────────────────────────
FROM node:20-bookworm-slim

# /api/connectivity shells out to `ping`, which node:20-bookworm-slim doesn't
# include by default.
RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Compiled Go binaries from the tools stage (default GOPATH is /root/go as root)
COPY --from=tools /root/go/bin/* /usr/local/bin/

WORKDIR /app
COPY backend/package*.json ./
RUN npm ci --omit=dev
COPY backend/ ./

ENV PORT=2000
EXPOSE 2000

# nuclei templates are pulled at container start rather than baked into the
# image, so the ruleset stays current without a rebuild.
CMD ["/bin/sh", "-c", "nuclei -update-templates -silent || true; exec node index.js"]
