# ══════════════════════════════════════════════════════════════════════════════
#  SentinelAI — Multi-stage Docker Build
#  Builds both backend and frontend into a single production image.
# ══════════════════════════════════════════════════════════════════════════════

# ── Stage 1: Build Frontend ──────────────────────────────────────────────────
FROM node:20-alpine AS frontend-build

WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm ci --production=false
COPY frontend/ ./
RUN npm run build

# ── Stage 2: Production Backend ──────────────────────────────────────────────
FROM node:20-alpine AS production

LABEL maintainer="SentinelAI"
LABEL description="AI-Powered Prompt Injection Firewall"

# Security: run as non-root user
RUN addgroup -g 1001 -S sentinel && \
    adduser -S sentinel -u 1001 -G sentinel

WORKDIR /app

# Install backend dependencies
COPY backend/package*.json ./backend/
RUN cd backend && npm ci --production && npm cache clean --force

# Copy backend source
COPY backend/ ./backend/

# Copy built frontend
COPY --from=frontend-build /app/frontend/dist ./frontend/dist

# Create necessary directories
RUN mkdir -p backend/logs backend/db && \
    chown -R sentinel:sentinel /app

# Switch to non-root user
USER sentinel

# Environment defaults
ENV NODE_ENV=production
ENV PORT=5000

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:5000/api/health || exit 1

WORKDIR /app/backend
CMD ["node", "server.js"]
