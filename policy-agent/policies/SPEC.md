# Policies Specification

## 1. Overview

This document describes policy implementations, the policy interface, development guidelines, and example implementations. All policies are compiled into the `policy-agent` binary and registered at startup.

## 2. Policy Interface

### 2.1 Required Interface

Every policy must implement the `Policy` interface defined in the Agent Core:

```go
package policies

import "context"

type Policy interface {
    // Name returns the unique identifier for this policy
    Name() string

    // Version returns the policy version (semver)
    Version() string

    // Description returns a human-readable description
    Description() string

    // SupportedPhases returns which phases this policy supports
    SupportedPhases() []PolicyPhase

    // MetadataSchema returns JSON schema for validating metadata
    MetadataSchema() string

    // Execute runs the policy logic
    Execute(ctx context.Context, metadata map[string]string, reqCtx *RequestContext) (*PolicyResult, error)

    // Initialize is called once when policy is registered
    Initialize(config map[string]interface{}) error

    // HealthCheck returns the health status of the policy
    HealthCheck() error
}

type PolicyPhase int

const (
    REQUEST PolicyPhase = iota
    RESPONSE
)
```

### 2.2 Policy Result

```go
type PolicyResult struct {
    Instructions []*Instruction  // Instructions to apply
    Status       StatusCode      // OK, POLICY_DENIED, POLICY_ERROR, TIMEOUT
    Message      string          // Human-readable message
    Metadata     map[string]string // Additional metadata for logging/tracing
}

type StatusCode int

const (
    OK StatusCode = iota
    POLICY_DENIED
    POLICY_ERROR
    TIMEOUT
)
```

### 2.3 Request Context

```go
type RequestContext struct {
    // Request properties (immutable after initial set)
    Headers      map[string]string
    Body         []byte
    Method       string
    Path         string
    Scheme       string
    Authority    string
    QueryParams  map[string]string
    ClientIP     string

    // Mutable state for policy chain (policies can read/write)
    State        map[string]interface{}
}
```

## 3. Instruction Types

### 3.1 Available Instructions

```go
type Instruction struct {
    Type    InstructionType
    Payload interface{}
}

type InstructionType int

const (
    SET_HEADER         InstructionType = iota  // Add/update header
    REMOVE_HEADER                              // Remove header
    SET_BODY                                   // Replace request/response body
    IMMEDIATE_RESPONSE                         // Return immediate response (terminal)
    CONTINUE                                   // Continue to next policy
    SET_STATE                                  // Update context state
)
```

### 3.2 Instruction Payloads

```go
// SET_HEADER
type HeaderInstruction struct {
    Key   string
    Value string
}

// REMOVE_HEADER
type HeaderInstruction struct {
    Key string
}

// SET_BODY
type BodyInstruction struct {
    Body []byte
}

// IMMEDIATE_RESPONSE (terminal - stops policy chain)
type ImmediateResponse struct {
    StatusCode int
    Headers    map[string]string
    Body       string
}

// SET_STATE
type StateInstruction struct {
    Key   string
    Value interface{}
}
```

## 4. Policy Development Guidelines

### 4.1 Best Practices

1. **Stateless Execution**: Policies should be stateless or use external state stores (Redis, databases)
2. **Timeout Awareness**: Respect context deadlines, implement timeout handling
3. **Error Handling**: Return errors for unexpected conditions, use `PolicyResult.Status` for policy decisions
4. **Resource Cleanup**: Release resources (connections, file handles) in all code paths
5. **Testing**: Each policy must have unit tests with 80%+ coverage
6. **Documentation**: Each policy must document its metadata schema and behavior
7. **Security**: Never log sensitive data (API keys, tokens, passwords)
8. **Performance**: Keep execution time under 50ms (P99)

### 4.2 Metadata Schema

Each policy must provide a JSON schema for its metadata:

```go
func (p *MyPolicy) MetadataSchema() string {
    return `{
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "properties": {
            "required_field": {
                "type": "string",
                "description": "Description of field"
            },
            "optional_field": {
                "type": "integer",
                "default": 100
            }
        },
        "required": ["required_field"]
    }`
}
```

### 4.3 Error Handling

```go
func (p *MyPolicy) Execute(ctx context.Context, metadata map[string]string, reqCtx *RequestContext) (*PolicyResult, error) {
    // Validate metadata
    if err := p.validateMetadata(metadata); err != nil {
        return &PolicyResult{
            Status:  POLICY_ERROR,
            Message: fmt.Sprintf("Invalid metadata: %v", err),
        }, err
    }

    // Check context deadline
    if deadline, ok := ctx.Deadline(); ok {
        if time.Until(deadline) < 10*time.Millisecond {
            return &PolicyResult{
                Status:  TIMEOUT,
                Message: "Insufficient time to execute",
            }, context.DeadlineExceeded
        }
    }

    // Execute policy logic...

    // Handle expected policy failure (e.g., auth failed)
    if !authorized {
        return &PolicyResult{
            Status:  POLICY_DENIED,
            Message: "Authorization failed",
            Instructions: []*Instruction{
                {
                    Type: IMMEDIATE_RESPONSE,
                    Payload: &ImmediateResponse{
                        StatusCode: 403,
                        Body:       `{"error": "Forbidden"}`,
                    },
                },
            },
        }, nil
    }

    // Success
    return &PolicyResult{
        Status:  OK,
        Message: "Policy passed",
        Instructions: []*Instruction{
            {
                Type: SET_HEADER,
                Payload: &HeaderInstruction{
                    Key:   "X-Policy-Result",
                    Value: "passed",
                },
            },
        },
    }, nil
}
```

## 5. Example Policy: API Key Authentication

### 5.1 Complete Implementation

```go
package apikey

import (
    "context"
    "fmt"
    "sync"
)

type APIKeyAuthPolicy struct {
    validKeys map[string]bool
    mu        sync.RWMutex
}

func NewAPIKeyPolicy() *APIKeyAuthPolicy {
    return &APIKeyAuthPolicy{
        validKeys: make(map[string]bool),
    }
}

func (p *APIKeyAuthPolicy) Name() string {
    return "apiKeyAuth"
}

func (p *APIKeyAuthPolicy) Version() string {
    return "1.0.0"
}

func (p *APIKeyAuthPolicy) Description() string {
    return "Validates API key from request header"
}

func (p *APIKeyAuthPolicy) SupportedPhases() []PolicyPhase {
    return []PolicyPhase{REQUEST}
}

func (p *APIKeyAuthPolicy) MetadataSchema() string {
    return `{
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "properties": {
            "header_name": {
                "type": "string",
                "description": "Header name containing API key",
                "default": "X-API-Key"
            },
            "required": {
                "type": "boolean",
                "description": "Whether API key is required",
                "default": true
            }
        }
    }`
}

func (p *APIKeyAuthPolicy) Initialize(config map[string]interface{}) error {
    // Load valid API keys from configuration or external store
    keys, ok := config["valid_keys"].([]string)
    if !ok {
        return fmt.Errorf("valid_keys must be a string array")
    }

    p.mu.Lock()
    defer p.mu.Unlock()

    for _, key := range keys {
        p.validKeys[key] = true
    }

    return nil
}

func (p *APIKeyAuthPolicy) HealthCheck() error {
    p.mu.RLock()
    defer p.mu.RUnlock()

    if len(p.validKeys) == 0 {
        return fmt.Errorf("no valid API keys configured")
    }

    return nil
}

func (p *APIKeyAuthPolicy) Execute(ctx context.Context, metadata map[string]string, reqCtx *RequestContext) (*PolicyResult, error) {
    headerName := metadata["header_name"]
    if headerName == "" {
        headerName = "X-API-Key"
    }

    required := metadata["required"] == "true"

    apiKey := reqCtx.Headers[headerName]

    // Missing API key
    if apiKey == "" {
        if required {
            return &PolicyResult{
                Status:  POLICY_DENIED,
                Message: "API key required",
                Instructions: []*Instruction{
                    {
                        Type: IMMEDIATE_RESPONSE,
                        Payload: &ImmediateResponse{
                            StatusCode: 401,
                            Headers: map[string]string{
                                "WWW-Authenticate": "API-Key",
                            },
                            Body: `{"error": "API key required"}`,
                        },
                    },
                },
            }, nil
        }
        return &PolicyResult{Status: OK}, nil
    }

    // Validate API key
    p.mu.RLock()
    valid := p.validKeys[apiKey]
    p.mu.RUnlock()

    if !valid {
        return &PolicyResult{
            Status:  POLICY_DENIED,
            Message: "Invalid API key",
            Instructions: []*Instruction{
                {
                    Type: IMMEDIATE_RESPONSE,
                    Payload: &ImmediateResponse{
                        StatusCode: 403,
                        Body:       `{"error": "Invalid API key"}`,
                    },
                },
            },
        }, nil
    }

    // API key valid - set user context for downstream policies
    userID := p.getUserIDFromAPIKey(apiKey)

    return &PolicyResult{
        Status:  OK,
        Message: "API key validated",
        Instructions: []*Instruction{
            {
                Type: SET_HEADER,
                Payload: &HeaderInstruction{
                    Key:   "X-User-ID",
                    Value: userID,
                },
            },
            {
                Type: SET_STATE,
                Payload: &StateInstruction{
                    Key:   "auth_method",
                    Value: "api_key",
                },
            },
        },
        Metadata: map[string]string{
            "auth_method": "api_key",
            "user_id":     userID,
        },
    }, nil
}

func (p *APIKeyAuthPolicy) getUserIDFromAPIKey(apiKey string) string {
    // In real implementation, lookup user from database or cache
    return "user-" + apiKey[:8]
}
```

### 5.2 Unit Tests

```go
package apikey_test

import (
    "context"
    "testing"
)

func TestAPIKeyAuth_ValidKey(t *testing.T) {
    policy := NewAPIKeyPolicy()
    policy.Initialize(map[string]interface{}{
        "valid_keys": []string{"valid-key-123"},
    })

    metadata := map[string]string{
        "header_name": "X-API-Key",
        "required":    "true",
    }

    reqCtx := &RequestContext{
        Headers: map[string]string{
            "X-API-Key": "valid-key-123",
        },
    }

    result, err := policy.Execute(context.Background(), metadata, reqCtx)

    if err != nil {
        t.Fatalf("Expected no error, got: %v", err)
    }

    if result.Status != OK {
        t.Errorf("Expected OK status, got: %v", result.Status)
    }

    if len(result.Instructions) != 2 {
        t.Errorf("Expected 2 instructions, got: %d", len(result.Instructions))
    }
}

func TestAPIKeyAuth_InvalidKey(t *testing.T) {
    policy := NewAPIKeyPolicy()
    policy.Initialize(map[string]interface{}{
        "valid_keys": []string{"valid-key-123"},
    })

    metadata := map[string]string{
        "header_name": "X-API-Key",
        "required":    "true",
    }

    reqCtx := &RequestContext{
        Headers: map[string]string{
            "X-API-Key": "invalid-key",
        },
    }

    result, err := policy.Execute(context.Background(), metadata, reqCtx)

    if err != nil {
        t.Fatalf("Expected no error, got: %v", err)
    }

    if result.Status != POLICY_DENIED {
        t.Errorf("Expected POLICY_DENIED status, got: %v", result.Status)
    }

    // Check for immediate response instruction
    if len(result.Instructions) == 0 {
        t.Fatal("Expected instructions")
    }

    inst := result.Instructions[0]
    if inst.Type != IMMEDIATE_RESPONSE {
        t.Errorf("Expected IMMEDIATE_RESPONSE, got: %v", inst.Type)
    }

    resp := inst.Payload.(*ImmediateResponse)
    if resp.StatusCode != 403 {
        t.Errorf("Expected 403 status, got: %d", resp.StatusCode)
    }
}

func TestAPIKeyAuth_MissingKeyRequired(t *testing.T) {
    policy := NewAPIKeyPolicy()
    policy.Initialize(map[string]interface{}{
        "valid_keys": []string{"valid-key-123"},
    })

    metadata := map[string]string{
        "header_name": "X-API-Key",
        "required":    "true",
    }

    reqCtx := &RequestContext{
        Headers: map[string]string{},
    }

    result, err := policy.Execute(context.Background(), metadata, reqCtx)

    if err != nil {
        t.Fatalf("Expected no error, got: %v", err)
    }

    if result.Status != POLICY_DENIED {
        t.Errorf("Expected POLICY_DENIED status, got: %v", result.Status)
    }

    resp := result.Instructions[0].Payload.(*ImmediateResponse)
    if resp.StatusCode != 401 {
        t.Errorf("Expected 401 status, got: %d", resp.StatusCode)
    }
}
```

## 6. Example Policy: JWT Validation

### 6.1 Implementation Outline

```go
package jwt

import (
    "context"
    "fmt"
    "github.com/golang-jwt/jwt/v5"
)

type JWTValidationPolicy struct {
    publicKey interface{}
}

func (p *JWTValidationPolicy) Name() string {
    return "jwtValidation"
}

func (p *JWTValidationPolicy) Execute(ctx context.Context, metadata map[string]string, reqCtx *RequestContext) (*PolicyResult, error) {
    issuer := metadata["issuer"]
    audience := metadata["audience"]

    // Extract JWT from Authorization header
    authHeader := reqCtx.Headers["Authorization"]
    if authHeader == "" {
        return p.denyResult(401, "Missing Authorization header"), nil
    }

    tokenString := extractBearerToken(authHeader)
    if tokenString == "" {
        return p.denyResult(401, "Invalid Authorization header format"), nil
    }

    // Validate JWT
    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        return p.publicKey, nil
    })

    if err != nil || !token.Valid {
        return p.denyResult(401, "Invalid JWT"), nil
    }

    // Validate claims
    claims, ok := token.Claims.(jwt.MapClaims)
    if !ok {
        return p.denyResult(401, "Invalid JWT claims"), nil
    }

    if !claims.VerifyIssuer(issuer, true) {
        return p.denyResult(403, "Invalid issuer"), nil
    }

    if !claims.VerifyAudience(audience, true) {
        return p.denyResult(403, "Invalid audience"), nil
    }

    // Extract user info and set headers
    userID := claims["sub"].(string)
    email := claims["email"].(string)

    return &PolicyResult{
        Status:  OK,
        Message: "JWT validated",
        Instructions: []*Instruction{
            {Type: SET_HEADER, Payload: &HeaderInstruction{Key: "X-User-ID", Value: userID}},
            {Type: SET_HEADER, Payload: &HeaderInstruction{Key: "X-User-Email", Value: email}},
            {Type: SET_STATE, Payload: &StateInstruction{Key: "auth_method", Value: "jwt"}},
        },
        Metadata: map[string]string{
            "auth_method": "jwt",
            "user_id":     userID,
        },
    }, nil
}
```

## 7. Example Policy: Rate Limiting

### 7.1 Implementation Outline

```go
package ratelimit

import (
    "context"
    "fmt"
    "golang.org/x/time/rate"
    "sync"
)

type RateLimitPolicy struct {
    limiters map[string]*rate.Limiter
    mu       sync.RWMutex
}

func (p *RateLimitPolicy) Name() string {
    return "rateLimit"
}

func (p *RateLimitPolicy) Execute(ctx context.Context, metadata map[string]string, reqCtx *RequestContext) (*PolicyResult, error) {
    requestsPerSecond := parseFloat(metadata["requests_per_second"], 100.0)
    burst := parseInt(metadata["burst"], 20)

    // Get identifier for rate limiting (could be IP, user ID, API key, etc.)
    identifier := reqCtx.ClientIP
    if userID := reqCtx.Headers["X-User-ID"]; userID != "" {
        identifier = userID
    }

    // Get or create limiter for this identifier
    limiter := p.getLimiter(identifier, requestsPerSecond, burst)

    // Check rate limit
    if !limiter.Allow() {
        return &PolicyResult{
            Status:  POLICY_DENIED,
            Message: "Rate limit exceeded",
            Instructions: []*Instruction{
                {
                    Type: IMMEDIATE_RESPONSE,
                    Payload: &ImmediateResponse{
                        StatusCode: 429,
                        Headers: map[string]string{
                            "Retry-After": "1",
                        },
                        Body: `{"error": "Too many requests"}`,
                    },
                },
            },
        }, nil
    }

    return &PolicyResult{
        Status:  OK,
        Message: "Rate limit check passed",
    }, nil
}

func (p *RateLimitPolicy) getLimiter(identifier string, rps float64, burst int) *rate.Limiter {
    p.mu.RLock()
    limiter, exists := p.limiters[identifier]
    p.mu.RUnlock()

    if exists {
        return limiter
    }

    p.mu.Lock()
    defer p.mu.Unlock()

    // Double-check after acquiring write lock
    if limiter, exists = p.limiters[identifier]; exists {
        return limiter
    }

    limiter = rate.NewLimiter(rate.Limit(rps), burst)
    p.limiters[identifier] = limiter
    return limiter
}
```

## 8. Policy Registration

### 8.1 Main Registration File

```go
// cmd/agent/main.go
package main

import (
    "github.com/policy-engine/policy-agent/internal/core"
    "github.com/policy-engine/policy-agent/internal/policies/apikey"
    "github.com/policy-engine/policy-agent/internal/policies/jwt"
    "github.com/policy-engine/policy-agent/internal/policies/ratelimit"
)

func main() {
    config := loadConfig()
    agent := core.NewAgent(config)

    // Register all policies
    registerPolicies(agent)

    // Start agent
    agent.Start()
}

func registerPolicies(agent *core.Agent) {
    agent.RegisterPolicy(apikey.NewAPIKeyPolicy())
    agent.RegisterPolicy(jwt.NewJWTPolicy())
    agent.RegisterPolicy(ratelimit.NewRateLimitPolicy())
    // Add more policies here
}
```

## 9. Testing Guidelines

### 9.1 Required Tests

1. **Happy Path**: Policy succeeds with valid input
2. **Policy Denial**: Policy correctly denies invalid requests
3. **Missing Metadata**: Handle missing required metadata
4. **Invalid Metadata**: Handle invalid metadata values
5. **Context Deadline**: Respect context timeouts
6. **Resource Limits**: Handle large bodies, excessive state
7. **Concurrent Execution**: Thread-safety for shared resources

### 9.2 Performance Benchmarks

```go
func BenchmarkAPIKeyAuth(b *testing.B) {
    policy := NewAPIKeyPolicy()
    policy.Initialize(map[string]interface{}{
        "valid_keys": []string{"valid-key-123"},
    })

    metadata := map[string]string{
        "header_name": "X-API-Key",
        "required":    "true",
    }

    reqCtx := &RequestContext{
        Headers: map[string]string{
            "X-API-Key": "valid-key-123",
        },
    }

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, _ = policy.Execute(context.Background(), metadata, reqCtx)
    }
}
```

---

## Document Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-11-02 | System | Extracted from v2.0 monolithic specification |
