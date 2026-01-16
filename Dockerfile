# GoTestWAF Multi-Protocol Echo Server
# Supports: HTTP/REST, GraphQL, gRPC, WebSocket
FROM node:20-alpine

# Install build dependencies for native modules
RUN apk add --no-cache python3 make g++ curl

WORKDIR /app

# Copy package files first for better caching
COPY package*.json ./

# Install dependencies
RUN npm install --production

# Copy application files
COPY . .

# Expose ports
# HTTP/REST/GraphQL/WebSocket
EXPOSE 8080
# gRPC
EXPOSE 50051

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

# Environment variables (can be overridden)
ENV HTTP_PORT=8080
ENV GRPC_PORT=50051
ENV NODE_ENV=production

# Run as non-root user for security
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

USER nodejs

# Start the server
CMD ["node", "server.js"]
