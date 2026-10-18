# ====================================================================
# BOS (Business Operating System) - Ultra-Lightweight Bun Container
# Single process, zero-bloat, WAL-mode SQLite persistence on /data
# ====================================================================

FROM oven/bun:1.1-alpine AS runner

WORKDIR /app

# Install minimal system utilities for healthcheck
RUN apk add --no-cache curl

# Create data directory and assign ownership to unprivileged bun user
RUN mkdir -p /data && chown -R bun:bun /data /app

# Copy project files with proper ownership
COPY --chown=bun:bun package.json ./
COPY --chown=bun:bun schema.sql ./
COPY --chown=bun:bun server.ts ./
COPY --chown=bun:bun index.html ./

USER bun

# Default Environment Variables
ENV NODE_ENV=production
ENV PORT=8080
ENV DATABASE_PATH=/data/bos.db

EXPOSE 8080

# Health check against Business Pulse API
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/api/pulse || exit 1

# Launch the unified server
CMD ["bun", "run", "server.ts"]
