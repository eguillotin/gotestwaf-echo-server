/**
 * Multi-Protocol Echo Server for GoTestWAF Testing
 * Supports: HTTP/HTTPS, REST API, gRPC, GraphQL, WebSocket
 * 
 * All protocols echo back request details for WAF testing
 */

const express = require('express');
const { ApolloServer } = require('@apollo/server');
const { expressMiddleware } = require('@apollo/server/express4');
const { createServer } = require('http');
const { createServer: createHttpsServer } = require('https');
const { WebSocketServer } = require('ws');
const grpc = require('@grpc/grpc-js');
const protoLoader = require('@grpc/proto-loader');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

// ============================================
// Configuration
// ============================================
const HTTP_PORT = process.env.HTTP_PORT || 8080;
const HTTPS_PORT = process.env.HTTPS_PORT || 8443;
const GRPC_PORT = process.env.GRPC_PORT || 50051;

// SSL Certificate paths
const SSL_CERT_PATH = process.env.SSL_CERT_PATH || '/app/fullchain.pem';
const SSL_KEY_PATH = process.env.SSL_KEY_PATH || '/app/privkey.pem';

// ============================================
// Express App Setup (HTTP/REST/GraphQL)
// ============================================
const app = express();

// Middleware to capture raw body for echo
app.use(bodyParser.raw({ type: '*/*', limit: '10mb' }));
app.use(cors());

// Request logging middleware
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// ============================================
// REST API Echo Endpoints
// ============================================

// Generic echo handler - returns all request details
const echoHandler = (req, res) => {
  const response = {
    timestamp: new Date().toISOString(),
    protocol: req.protocol,
    method: req.method,
    path: req.path,
    url: req.url,
    originalUrl: req.originalUrl,
    headers: req.headers,
    query: req.query,
    params: req.params,
    body: req.body ? req.body.toString('utf-8') : null,
    ip: req.ip,
    cookies: req.cookies || {},
    hostname: req.hostname
  };

  // Set response headers for testing
  res.set('X-Echo-Server', 'gotestwaf-multi-protocol');
  res.set('X-Request-Method', req.method);
  res.set('X-Request-Path', req.path);
  
  res.json(response);
};

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'healthy', protocols: ['http', 'rest', 'graphql', 'grpc', 'websocket'] });
});

// REST API endpoints - all HTTP methods
app.all('/api/*', echoHandler);
app.all('/rest/*', echoHandler);

// GoTestWAF specific endpoints
app.all('/get', echoHandler);
app.all('/post', echoHandler);
app.all('/put', echoHandler);
app.all('/patch', echoHandler);
app.all('/delete', echoHandler);
app.all('/options', echoHandler);

// Path traversal test endpoints
app.all('/path/*', echoHandler);
app.all('/file/*', echoHandler);

// Authentication test endpoints
app.all('/login', echoHandler);
app.all('/auth/*', echoHandler);
app.all('/admin/*', echoHandler);
app.all('/user/*', echoHandler);

// Common vulnerable endpoints for WAF testing
app.all('/search', echoHandler);
app.all('/query', echoHandler);
app.all('/exec', echoHandler);
app.all('/cmd', echoHandler);
app.all('/eval', echoHandler);
app.all('/upload', echoHandler);
app.all('/download', echoHandler);
app.all('/include', echoHandler);
app.all('/redirect', echoHandler);

// Catch-all for any other paths
app.all('*', echoHandler);

// ============================================
// GraphQL Setup
// ============================================

// GraphQL type definitions
const typeDefs = `#graphql
  type Query {
    echo(input: String): EchoResponse
    search(query: String!, limit: Int): SearchResponse
    user(id: ID!): User
    users(filter: UserFilter): [User]
    file(path: String!): FileResponse
    exec(command: String!): ExecResponse
  }

  type Mutation {
    createUser(input: UserInput!): User
    updateUser(id: ID!, input: UserInput!): User
    deleteUser(id: ID!): Boolean
    uploadFile(name: String!, content: String!): FileResponse
    executeCommand(cmd: String!): ExecResponse
    login(username: String!, password: String!): AuthResponse
  }

  type Subscription {
    messageAdded: Message
  }

  type EchoResponse {
    timestamp: String
    input: String
    headers: String
  }

  type SearchResponse {
    query: String
    results: [String]
    count: Int
  }

  type User {
    id: ID
    username: String
    email: String
    role: String
  }

  type FileResponse {
    path: String
    content: String
    size: Int
  }

  type ExecResponse {
    command: String
    output: String
    exitCode: Int
  }

  type AuthResponse {
    token: String
    user: User
  }

  type Message {
    id: ID
    content: String
  }

  input UserInput {
    username: String
    email: String
    password: String
    role: String
  }

  input UserFilter {
    role: String
    search: String
  }
`;

// GraphQL resolvers - all echo back the input for testing
const resolvers = {
  Query: {
    echo: (_, { input }, context) => ({
      timestamp: new Date().toISOString(),
      input: input || 'no input',
      headers: JSON.stringify(context.headers || {})
    }),
    search: (_, { query, limit }) => ({
      query,
      results: [`Result for: ${query}`],
      count: 1
    }),
    user: (_, { id }) => ({
      id,
      username: `user_${id}`,
      email: `user_${id}@example.com`,
      role: 'user'
    }),
    users: (_, { filter }) => [{
      id: '1',
      username: 'test_user',
      email: 'test@example.com',
      role: filter?.role || 'user'
    }],
    file: (_, { path }) => ({
      path,
      content: `Content of file: ${path}`,
      size: 100
    }),
    exec: (_, { command }) => ({
      command,
      output: `Echoed command: ${command}`,
      exitCode: 0
    })
  },
  Mutation: {
    createUser: (_, { input }) => ({
      id: Date.now().toString(),
      ...input
    }),
    updateUser: (_, { id, input }) => ({
      id,
      ...input
    }),
    deleteUser: () => true,
    uploadFile: (_, { name, content }) => ({
      path: `/uploads/${name}`,
      content,
      size: content.length
    }),
    executeCommand: (_, { cmd }) => ({
      command: cmd,
      output: `Echoed: ${cmd}`,
      exitCode: 0
    }),
    login: (_, { username, password }) => ({
      token: `token_for_${username}`,
      user: {
        id: '1',
        username,
        email: `${username}@example.com`,
        role: 'user'
      }
    })
  }
};

// ============================================
// gRPC Setup
// ============================================

// Load proto definition
const PROTO_PATH = path.join(__dirname, 'proto', 'echo.proto');
const packageDefinition = protoLoader.loadSync(PROTO_PATH, {
  keepCase: true,
  longs: String,
  enums: String,
  defaults: true,
  oneofs: true
});

const echoProto = grpc.loadPackageDefinition(packageDefinition).echo;

// gRPC service implementations
const grpcServices = {
  // Unary echo
  Echo: (call, callback) => {
    console.log(`[gRPC] Echo request: ${call.request.message}`);
    callback(null, {
      message: call.request.message,
      timestamp: new Date().toISOString(),
      metadata: JSON.stringify(call.metadata.getMap())
    });
  },
  
  // Server streaming
  ServerStream: (call) => {
    console.log(`[gRPC] ServerStream request: ${call.request.message}`);
    for (let i = 0; i < 5; i++) {
      call.write({
        message: `Stream ${i}: ${call.request.message}`,
        timestamp: new Date().toISOString(),
        metadata: ''
      });
    }
    call.end();
  },
  
  // Client streaming
  ClientStream: (call, callback) => {
    const messages = [];
    call.on('data', (request) => {
      console.log(`[gRPC] ClientStream data: ${request.message}`);
      messages.push(request.message);
    });
    call.on('end', () => {
      callback(null, {
        message: `Received ${messages.length} messages: ${messages.join(', ')}`,
        timestamp: new Date().toISOString(),
        metadata: ''
      });
    });
  },
  
  // Bidirectional streaming
  BidiStream: (call) => {
    call.on('data', (request) => {
      console.log(`[gRPC] BidiStream data: ${request.message}`);
      call.write({
        message: `Echo: ${request.message}`,
        timestamp: new Date().toISOString(),
        metadata: ''
      });
    });
    call.on('end', () => {
      call.end();
    });
  },

  // Search endpoint for testing
  Search: (call, callback) => {
    console.log(`[gRPC] Search request: ${call.request.query}`);
    callback(null, {
      message: `Search results for: ${call.request.query}`,
      timestamp: new Date().toISOString(),
      metadata: ''
    });
  },

  // Execute command (for testing command injection detection)
  Execute: (call, callback) => {
    console.log(`[gRPC] Execute request: ${call.request.command}`);
    callback(null, {
      message: `Command echoed: ${call.request.command}`,
      timestamp: new Date().toISOString(),
      metadata: ''
    });
  },

  // File read (for testing path traversal detection)
  ReadFile: (call, callback) => {
    console.log(`[gRPC] ReadFile request: ${call.request.path}`);
    callback(null, {
      message: `File path echoed: ${call.request.path}`,
      timestamp: new Date().toISOString(),
      metadata: ''
    });
  }
};

// ============================================
// WebSocket Setup
// ============================================

function setupWebSocket(server) {
  const wss = new WebSocketServer({ server, path: '/ws' });
  
  wss.on('connection', (ws, req) => {
    console.log(`[WebSocket] New connection from ${req.socket.remoteAddress}`);
    
    ws.on('message', (message) => {
      const messageStr = message.toString();
      console.log(`[WebSocket] Received: ${messageStr}`);
      
      // Echo back with metadata
      const response = JSON.stringify({
        type: 'echo',
        timestamp: new Date().toISOString(),
        original: messageStr,
        headers: req.headers
      });
      
      ws.send(response);
    });
    
    ws.on('close', () => {
      console.log('[WebSocket] Connection closed');
    });
    
    ws.on('error', (error) => {
      console.error('[WebSocket] Error:', error);
    });
    
    // Send welcome message
    ws.send(JSON.stringify({
      type: 'welcome',
      message: 'Connected to GoTestWAF Echo Server',
      timestamp: new Date().toISOString()
    }));
  });
  
  return wss;
}

// ============================================
// Server Startup
// ============================================

async function startServer() {
  // Create HTTP server
  const httpServer = createServer(app);
  
  // Setup WebSocket on HTTP
  setupWebSocket(httpServer);
  
  // Setup Apollo GraphQL Server
  const apolloServer = new ApolloServer({
    typeDefs,
    resolvers,
    introspection: true,  // Enable introspection for testing
  });
  
  await apolloServer.start();
  
  // Mount GraphQL at /graphql
  app.use('/graphql', 
    express.json(),
    expressMiddleware(apolloServer, {
      context: async ({ req }) => ({ headers: req.headers })
    })
  );
  
  // Start HTTP server
  httpServer.listen(HTTP_PORT, '0.0.0.0', () => {
    console.log(`[HTTP] Server running on port ${HTTP_PORT}`);
  });

  // Start HTTPS server if certificates exist
  if (fs.existsSync(SSL_CERT_PATH) && fs.existsSync(SSL_KEY_PATH)) {
    try {
      const sslOptions = {
        cert: fs.readFileSync(SSL_CERT_PATH),
        key: fs.readFileSync(SSL_KEY_PATH)
      };
      
      const httpsServer = createHttpsServer(sslOptions, app);
      
      // Setup WebSocket on HTTPS
      setupWebSocket(httpsServer);
      
      httpsServer.listen(HTTPS_PORT, '0.0.0.0', () => {
        console.log(`[HTTPS] Server running on port ${HTTPS_PORT}`);
      });
    } catch (err) {
      console.error('[HTTPS] Failed to start:', err.message);
    }
  } else {
    console.log('[HTTPS] Certificates not found, skipping HTTPS');
  }

  // Print banner after servers start
  setTimeout(() => {
    console.log(`
╔══════════════════════════════════════════════════════════════╗
║     GoTestWAF Multi-Protocol Echo Server                     ║
╠══════════════════════════════════════════════════════════════╣
║  HTTP/REST   : http://0.0.0.0:${HTTP_PORT}                          ║
║  HTTPS/REST  : https://0.0.0.0:${HTTPS_PORT}                         ║
║  GraphQL     : http(s)://0.0.0.0:${HTTP_PORT}/graphql               ║
║  WebSocket   : ws(s)://0.0.0.0:${HTTP_PORT}/ws                      ║
║  gRPC        : grpc://0.0.0.0:${GRPC_PORT}                         ║
╠══════════════════════════════════════════════════════════════╣
║  Health Check: http(s)://0.0.0.0:${HTTP_PORT}/health                ║
╚══════════════════════════════════════════════════════════════╝
    `);
  }, 100);
  
  // Start gRPC server
  const grpcServer = new grpc.Server();
  grpcServer.addService(echoProto.EchoService.service, grpcServices);
  
  grpcServer.bindAsync(
    `0.0.0.0:${GRPC_PORT}`,
    grpc.ServerCredentials.createInsecure(),
    (error, port) => {
      if (error) {
        console.error('gRPC server failed to start:', error);
        return;
      }
      console.log(`[gRPC] Server running on port ${port}`);
    }
  );
}

// Handle graceful shutdown
process.on('SIGTERM', () => {
  console.log('Shutting down...');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('Shutting down...');
  process.exit(0);
});

// Start the server
startServer().catch(console.error);