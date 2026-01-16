package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/graphql-go/graphql"
	"github.com/graphql-go/handler"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/reflection"

	pb "echo-server/proto"
)

// EchoResponse represents the standard echo response
type EchoResponse struct {
	Timestamp   string              `json:"timestamp"`
	Method      string              `json:"method"`
	Path        string              `json:"path"`
	Protocol    string              `json:"protocol"`
	Headers     map[string][]string `json:"headers"`
	QueryParams map[string][]string `json:"query_params,omitempty"`
	Body        string              `json:"body,omitempty"`
	RemoteAddr  string              `json:"remote_addr"`
	Host        string              `json:"host"`
}

// ================== HTTP/REST Echo Handler ==================

func echoHandler(w http.ResponseWriter, r *http.Request) {
	// Read body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		body = []byte{}
	}
	defer r.Body.Close()

	// Build response
	response := EchoResponse{
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		Method:      r.Method,
		Path:        r.URL.Path,
		Protocol:    r.Proto,
		Headers:     r.Header,
		QueryParams: r.URL.Query(),
		Body:        string(body),
		RemoteAddr:  r.RemoteAddr,
		Host:        r.Host,
	}

	// Set response headers
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Echo-Server", "gotestwaf-multi-protocol")

	// Echo back all request headers with X-Echo- prefix
	for key, values := range r.Header {
		for _, value := range values {
			w.Header().Add("X-Echo-"+key, value)
		}
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// Catch-all handler that echoes everything
func catchAllHandler(w http.ResponseWriter, r *http.Request) {
	echoHandler(w, r)
}

// REST API specific endpoints
func restAPIHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	body, _ := io.ReadAll(r.Body)
	defer r.Body.Close()

	response := map[string]interface{}{
		"timestamp":    time.Now().UTC().Format(time.RFC3339),
		"method":       r.Method,
		"endpoint":     r.URL.Path,
		"path_vars":    vars,
		"query_params": r.URL.Query(),
		"headers":      r.Header,
		"body":         string(body),
		"protocol":     "REST",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// ================== GraphQL Handler ==================

func createGraphQLHandler() *handler.Handler {
	// Define the Echo type
	echoType := graphql.NewObject(graphql.ObjectConfig{
		Name: "Echo",
		Fields: graphql.Fields{
			"message": &graphql.Field{
				Type: graphql.String,
			},
			"timestamp": &graphql.Field{
				Type: graphql.String,
			},
			"input": &graphql.Field{
				Type: graphql.String,
			},
			"headers": &graphql.Field{
				Type: graphql.String,
			},
		},
	})

	// Define User type for typical API patterns
	userType := graphql.NewObject(graphql.ObjectConfig{
		Name: "User",
		Fields: graphql.Fields{
			"id": &graphql.Field{
				Type: graphql.String,
			},
			"name": &graphql.Field{
				Type: graphql.String,
			},
			"email": &graphql.Field{
				Type: graphql.String,
			},
			"input": &graphql.Field{
				Type: graphql.String,
			},
		},
	})

	// Query type
	queryType := graphql.NewObject(graphql.ObjectConfig{
		Name: "Query",
		Fields: graphql.Fields{
			"echo": &graphql.Field{
				Type: echoType,
				Args: graphql.FieldConfigArgument{
					"message": &graphql.ArgumentConfig{
						Type: graphql.String,
					},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					message, _ := p.Args["message"].(string)
					return map[string]interface{}{
						"message":   message,
						"timestamp": time.Now().UTC().Format(time.RFC3339),
						"input":     message,
						"headers":   "echoed via GraphQL",
					}, nil
				},
			},
			"user": &graphql.Field{
				Type: userType,
				Args: graphql.FieldConfigArgument{
					"id": &graphql.ArgumentConfig{
						Type: graphql.String,
					},
					"name": &graphql.ArgumentConfig{
						Type: graphql.String,
					},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					id, _ := p.Args["id"].(string)
					name, _ := p.Args["name"].(string)
					return map[string]interface{}{
						"id":    id,
						"name":  name,
						"email": fmt.Sprintf("%s@echo.test", id),
						"input": fmt.Sprintf("id=%s, name=%s", id, name),
					}, nil
				},
			},
			"search": &graphql.Field{
				Type: graphql.NewList(echoType),
				Args: graphql.FieldConfigArgument{
					"query": &graphql.ArgumentConfig{
						Type: graphql.String,
					},
					"filter": &graphql.ArgumentConfig{
						Type: graphql.String,
					},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					query, _ := p.Args["query"].(string)
					filter, _ := p.Args["filter"].(string)
					return []map[string]interface{}{
						{
							"message":   fmt.Sprintf("Search result for: %s", query),
							"timestamp": time.Now().UTC().Format(time.RFC3339),
							"input":     fmt.Sprintf("query=%s, filter=%s", query, filter),
						},
					}, nil
				},
			},
		},
	})

	// Mutation type
	mutationType := graphql.NewObject(graphql.ObjectConfig{
		Name: "Mutation",
		Fields: graphql.Fields{
			"createEcho": &graphql.Field{
				Type: echoType,
				Args: graphql.FieldConfigArgument{
					"message": &graphql.ArgumentConfig{
						Type: graphql.NewNonNull(graphql.String),
					},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					message := p.Args["message"].(string)
					return map[string]interface{}{
						"message":   message,
						"timestamp": time.Now().UTC().Format(time.RFC3339),
						"input":     message,
						"headers":   "mutation echoed",
					}, nil
				},
			},
			"updateUser": &graphql.Field{
				Type: userType,
				Args: graphql.FieldConfigArgument{
					"id": &graphql.ArgumentConfig{
						Type: graphql.NewNonNull(graphql.String),
					},
					"name": &graphql.ArgumentConfig{
						Type: graphql.String,
					},
					"email": &graphql.ArgumentConfig{
						Type: graphql.String,
					},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					id := p.Args["id"].(string)
					name, _ := p.Args["name"].(string)
					email, _ := p.Args["email"].(string)
					return map[string]interface{}{
						"id":    id,
						"name":  name,
						"email": email,
						"input": fmt.Sprintf("updated: id=%s", id),
					}, nil
				},
			},
		},
	})

	// Create schema
	schema, err := graphql.NewSchema(graphql.SchemaConfig{
		Query:    queryType,
		Mutation: mutationType,
	})
	if err != nil {
		log.Fatalf("Failed to create GraphQL schema: %v", err)
	}

	return handler.New(&handler.Config{
		Schema:   &schema,
		Pretty:   true,
		GraphiQL: true,
	})
}

// ================== gRPC Server ==================

type grpcEchoServer struct {
	pb.UnimplementedEchoServiceServer
}

func (s *grpcEchoServer) Echo(ctx context.Context, req *pb.EchoRequest) (*pb.EchoResponse, error) {
	// Get metadata (headers)
	md, _ := metadata.FromIncomingContext(ctx)
	headers := make(map[string]string)
	for k, v := range md {
		headers[k] = strings.Join(v, ", ")
	}

	headersJSON, _ := json.Marshal(headers)

	return &pb.EchoResponse{
		Message:   req.Message,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Headers:   string(headersJSON),
		Protocol:  "gRPC",
	}, nil
}

func (s *grpcEchoServer) StreamEcho(stream pb.EchoService_StreamEchoServer) error {
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}

		resp := &pb.EchoResponse{
			Message:   req.Message,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Protocol:  "gRPC-Stream",
		}

		if err := stream.Send(resp); err != nil {
			return err
		}
	}
}

func startGRPCServer(port string) *grpc.Server {
	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("Failed to listen on gRPC port %s: %v", port, err)
	}

	grpcServer := grpc.NewServer()
	pb.RegisterEchoServiceServer(grpcServer, &grpcEchoServer{})

	// Enable reflection for grpcurl and testing tools
	reflection.Register(grpcServer)

	go func() {
		log.Printf("gRPC server listening on %s", port)
		if err := grpcServer.Serve(lis); err != nil {
			log.Printf("gRPC server error: %v", err)
		}
	}()

	return grpcServer
}

// ================== Main ==================

func main() {
	httpPort := getEnv("HTTP_PORT", ":8080")
	grpcPort := getEnv("GRPC_PORT", ":50051")

	// Create router
	router := mux.NewRouter()

	// Health check endpoint
	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":    "healthy",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"protocols": "HTTP, REST, GraphQL, gRPC",
		})
	}).Methods("GET")

	// GraphQL endpoint
	graphqlHandler := createGraphQLHandler()
	router.Handle("/graphql", graphqlHandler)
	router.Handle("/graphql/", graphqlHandler)

	// REST API endpoints with path parameters
	router.HandleFunc("/api/v1/users", restAPIHandler).Methods("GET", "POST", "PUT", "DELETE", "PATCH")
	router.HandleFunc("/api/v1/users/{id}", restAPIHandler).Methods("GET", "POST", "PUT", "DELETE", "PATCH")
	router.HandleFunc("/api/v1/users/{id}/profile", restAPIHandler).Methods("GET", "POST", "PUT", "DELETE", "PATCH")
	router.HandleFunc("/api/v1/products", restAPIHandler).Methods("GET", "POST", "PUT", "DELETE", "PATCH")
	router.HandleFunc("/api/v1/products/{id}", restAPIHandler).Methods("GET", "POST", "PUT", "DELETE", "PATCH")
	router.HandleFunc("/api/v1/orders", restAPIHandler).Methods("GET", "POST", "PUT", "DELETE", "PATCH")
	router.HandleFunc("/api/v1/orders/{id}", restAPIHandler).Methods("GET", "POST", "PUT", "DELETE", "PATCH")
	router.HandleFunc("/api/v1/search", restAPIHandler).Methods("GET", "POST")
	router.HandleFunc("/api/v1/{resource}", restAPIHandler).Methods("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS")
	router.HandleFunc("/api/v1/{resource}/{id}", restAPIHandler).Methods("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS")
	router.HandleFunc("/api/v2/{resource}", restAPIHandler).Methods("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS")
	router.HandleFunc("/api/v2/{resource}/{id}", restAPIHandler).Methods("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS")
	router.HandleFunc("/api/{version}/{resource}", restAPIHandler).Methods("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS")
	router.HandleFunc("/api/{version}/{resource}/{id}", restAPIHandler).Methods("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS")

	// OpenAPI/Swagger endpoint (returns a basic spec)
	router.HandleFunc("/openapi.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(openAPISpec))
	}).Methods("GET")

	router.HandleFunc("/swagger.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(openAPISpec))
	}).Methods("GET")

	// Classic WAF test endpoints
	router.HandleFunc("/", echoHandler)
	router.HandleFunc("/echo", echoHandler)
	router.HandleFunc("/login", echoHandler).Methods("GET", "POST")
	router.HandleFunc("/admin", echoHandler)
	router.HandleFunc("/admin/{path:.*}", echoHandler)
	router.HandleFunc("/upload", echoHandler).Methods("GET", "POST", "PUT")
	router.HandleFunc("/search", echoHandler)
	router.HandleFunc("/callback", echoHandler)
	router.HandleFunc("/webhook", echoHandler).Methods("GET", "POST")

	// Catch-all for any other path - MUST be last
	router.PathPrefix("/").HandlerFunc(catchAllHandler)

	// Start gRPC server
	grpcServer := startGRPCServer(grpcPort)

	// Create HTTP server
	httpServer := &http.Server{
		Addr:         httpPort,
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start HTTP server
	go func() {
		log.Printf("HTTP/REST/GraphQL server listening on %s", httpPort)
		log.Printf("  - HTTP Echo: http://localhost%s/echo", httpPort)
		log.Printf("  - REST API:  http://localhost%s/api/v1/users", httpPort)
		log.Printf("  - GraphQL:   http://localhost%s/graphql", httpPort)
		log.Printf("  - Health:    http://localhost%s/health", httpPort)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down servers...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	grpcServer.GracefulStop()
	httpServer.Shutdown(ctx)

	log.Println("Servers stopped")
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// OpenAPI specification for REST API testing
const openAPISpec = `{
  "openapi": "3.0.0",
  "info": {
    "title": "GoTestWAF Echo Server API",
    "version": "1.0.0",
    "description": "Multi-protocol echo server for WAF testing"
  },
  "servers": [
    {"url": "http://localhost:8080"}
  ],
  "paths": {
    "/api/v1/users": {
      "get": {
        "summary": "List users",
        "parameters": [
          {"name": "query", "in": "query", "schema": {"type": "string"}},
          {"name": "filter", "in": "query", "schema": {"type": "string"}}
        ],
        "responses": {"200": {"description": "Success"}}
      },
      "post": {
        "summary": "Create user",
        "requestBody": {
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "properties": {
                  "name": {"type": "string"},
                  "email": {"type": "string"}
                }
              }
            }
          }
        },
        "responses": {"200": {"description": "Success"}}
      }
    },
    "/api/v1/users/{id}": {
      "get": {
        "summary": "Get user by ID",
        "parameters": [
          {"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}
        ],
        "responses": {"200": {"description": "Success"}}
      },
      "put": {
        "summary": "Update user",
        "parameters": [
          {"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}
        ],
        "requestBody": {
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "properties": {
                  "name": {"type": "string"},
                  "email": {"type": "string"}
                }
              }
            }
          }
        },
        "responses": {"200": {"description": "Success"}}
      },
      "delete": {
        "summary": "Delete user",
        "parameters": [
          {"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}
        ],
        "responses": {"200": {"description": "Success"}}
      }
    },
    "/api/v1/search": {
      "get": {
        "summary": "Search",
        "parameters": [
          {"name": "q", "in": "query", "schema": {"type": "string"}},
          {"name": "page", "in": "query", "schema": {"type": "integer"}},
          {"name": "limit", "in": "query", "schema": {"type": "integer"}}
        ],
        "responses": {"200": {"description": "Success"}}
      }
    }
  }
}`
