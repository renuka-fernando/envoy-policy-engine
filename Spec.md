# Policy Engine Specification

## 1. Executive Summary

Policy Engine is an implementation of Envoy Proxy's External Processing Filter (v1.36.2) that provides extensible, route-based policy enforcement. The engine executes configurable policy chains to make routing decisions, apply authentication, authorization, rate limiting, and other cross-cutting concerns.

## 2. System Architecture

### 2.1 High-Level Architecture

```mermaid
graph TB
    Envoy[Envoy Proxy v1.36.2]

    Envoy -->|gRPC<br/>External Processing API| Container

    subgraph Container ["Docker Container: policy-engine"]
        direction TB
        subgraph Kernel["Policy Kernel"]
            K0[External Processing API gRPC Server]
            K1[Route-to-Policy Mapping]
            K2[Agent Registry]
            K3[Request Routing & Response Aggregation]
        end

        subgraph Agent["Policy Agent"]
            direction TB
            subgraph Core["Agent Core"]
                C0[Agent gRPC Server]
                C1[Policy Registry]
                C2[Sequential Policy Execution]
                C3[Request Context Management]
            end

            subgraph Policies["Policy Implementations"]
                P1[apiKeyAuth]
                P2[jwtValidation]
                P3[rateLimit]
                P4[customPolicy 1..n]
            end

            Core --> Policies
        end

        Kernel -->|gRPC over UDS| Agent
    end

    style Envoy fill:#e1f5ff
    style Container fill:#f5f5f5,stroke:#333,stroke-width:3px
    style Kernel fill:#fff4e1
    style Agent fill:#e8f5e9
    style Core fill:#e0f7fa
    style Policies fill:#fce4ec
```

### 2.2 Component Overview

The Policy Engine consists of two main components running in a single Docker container:

| Component | Description | Technology | Location |
|-----------|-------------|------------|----------|
| **Policy Kernel** | Envoy integration layer, route mapping, agent orchestration | Go binary | `/usr/local/bin/policy-kernel` |
| **Policy Agent** | Policy execution runtime with compiled-in policies | Go binary | `/usr/local/bin/policy-agent-1` |

**Communication:**
- Envoy ↔ Policy Kernel: gRPC over TCP (port 9001)
- Policy Kernel ↔ Policy Agent: gRPC over Unix Domain Socket (UDS)

### 2.3 Deployment Model

```mermaid
graph TB
    subgraph DockerContainer["Docker Container: policy-engine"]
        Supervisor[Supervisord Process Manager]

        subgraph Process1["Process 1: policy-kernel"]
            KernelBinary[policy-kernel]
            KernelConfig[Config: /etc/policy-engine/kernel-config.yaml]
            KernelBinary -.reads.- KernelConfig
        end

        subgraph Process2["Process 2: policy-agent"]
            AgentBinary[policy-agent]
            AgentConfig[Config: /etc/policy-engine/agent-config-1.yaml]
            AgentBinary -.reads.- AgentConfig
        end

        subgraph FileSystem["Shared File System"]
            UDSSocket[UDS Socket: /var/run/policy-engine/agents/agent-name-1.sock]
            Logs[/var/log/policy-engine/]
        end

        Supervisor -->|manages| Process1
        Supervisor -->|manages| Process2
        Process1 -->|writes to| UDSSocket
        Process2 -->|reads from| UDSSocket
        Process1 -.logs.-> Logs
        Process2 -.logs.-> Logs
    end

    EnvoyExternal[Envoy Proxy<br/>External to Container]
    EnvoyExternal -->|TCP :9001<br/>gRPC| Process1

    style DockerContainer fill:#f0f0f0,stroke:#333,stroke-width:3px
    style Process1 fill:#fff4e1
    style Process2 fill:#e8f5e9
    style FileSystem fill:#e3f2fd
    style Supervisor fill:#fff9c4
```

**Key Points:**

- **Container**: Single Docker container containing two separate binaries
- **Process Architecture**:
  - Both binaries run as independent processes within the same container
  - Managed by supervisord for process supervision and restart
  - Each process has its own lifecycle and can be restarted independently
- **File System Layout**:
  - `/usr/local/bin/policy-kernel` - Policy Kernel binary
  - `/usr/local/bin/policy-agent-1` - Policy Agent binary (multiple, default to 1)
  - `/var/run/policy-engine/agents/` - Directory for UDS sockets
  - `/etc/policy-engine/` - Configuration files directory
  - `/var/log/policy-engine/` - Log files directory

## 3. Request Flow (End-to-End)

```mermaid
sequenceDiagram
    participant Client
    participant Envoy as Envoy Proxy
    participant Kernel as Policy Kernel
    participant Agent as Policy Agent
    participant Policies as Policy Implementations
    participant Upstream

    Client->>Envoy: HTTP/HTTPS Request

    Note over Envoy: External Processing<br/>Filter Triggered

    Envoy->>Kernel: External Processing Request<br/>(route_name, headers, body)

    Note over Kernel: 1. Lookup route<br/>2. Select policies<br/>3. Find agent

    Kernel->>Agent: PolicyRequest (gRPC/UDS)<br/>(policies, metadata, context)

    Note over Agent: Agent Core receives request

    loop For each policy
        Agent->>Policies: Execute(metadata, context)
        Policies-->>Agent: PolicyResult (instructions)
        Note over Agent: Update context<br/>Collect instructions<br/>Check for early termination
    end

    Agent-->>Kernel: PolicyResponse<br/>(aggregated instructions)

    Note over Kernel: Convert to Envoy format

    Kernel-->>Envoy: External Processing Response<br/>(continue/modify/deny)

    alt Request Allowed
        Envoy->>Upstream: Forward Request<br/>(with modifications)
        Upstream-->>Envoy: Response
        Envoy-->>Client: Response
    else Request Denied
        Envoy-->>Client: Immediate Response<br/>(401/403/etc)
    end
```

### 3.2 Response Flow (End-to-End)

```mermaid
sequenceDiagram
    participant Upstream
    participant Envoy as Envoy Proxy
    participant Kernel as Policy Kernel
    participant Agent as Policy Agent
    participant Policies as Policy Implementations
    participant Client

    Upstream->>Envoy: HTTP Response

    Note over Envoy: External Processing<br/>Filter Triggered<br/>(Response Phase)

    Envoy->>Kernel: External Processing Response<br/>(route_name, headers, body)

    Note over Kernel: 1. Lookup route<br/>2. Select response policies<br/>3. Find agent

    Kernel->>Agent: PolicyRequest (gRPC/UDS)<br/>(policies, metadata, context)

    Note over Agent: Agent Core receives request

    loop For each policy
        Agent->>Policies: Execute(metadata, context)
        Policies-->>Agent: PolicyResult (instructions)
        Note over Agent: Update context<br/>Collect instructions<br/>Check for early termination
    end

    Agent-->>Kernel: PolicyResponse<br/>(aggregated instructions)

    Note over Kernel: Convert to Envoy format

    Kernel-->>Envoy: External Processing Response<br/>(continue/modify)

    Envoy->>Envoy: Apply Response Modifications<br/>(headers, body)

    Envoy-->>Client: Modified Response
```

## 4. Component Specifications

Detailed specifications for each component:

- **[Policy Kernel](policy-kernel/SPEC.md)** - Envoy integration, route mapping, agent management
- **[Policy Agent](policy-agent/SPEC.md)** - Policy execution runtime
  - **[Agent Core](policy-agent/agent-core/SPEC.md)** - Execution engine and policy registry
  - **[Policies](policy-agent/policies/SPEC.md)** - Policy implementations and development guide

## 5. Security Considerations

### 5.1 Inter-Component Security

- **UDS Permissions**: Socket files must have 0600 permissions, owned by policy-engine user
- **Process Isolation**: Run components as non-root user
- **Resource Limits**: Enforce memory and CPU limits via cgroups
- **Input Validation**: Validate all inputs from Envoy and agents

### 5.2 Container Security

- Non-root user (UID 1000)
- Read-only root filesystem (except /var/run and /var/log)
- No privilege escalation
- Minimal base image (Alpine Linux)

## 6. Observability

### 6.1 Metrics (Prometheus format)

**Policy Kernel:**
- `policy_kernel_requests_total{route, agent, status}` - Counter
- `policy_kernel_request_duration_seconds{route, agent}` - Histogram
- `policy_kernel_agent_health{agent}` - Gauge (0=unhealthy, 1=healthy)

**Policy Agent:**
- `policy_agent_executions_total{policy, status}` - Counter
- `policy_agent_execution_duration_seconds{policy}` - Histogram
- `policy_agent_policy_failures_total{policy, reason}` - Counter

### 6.2 Logging

**Structured JSON logs with fields:**
- `timestamp` (ISO8601)
- `level` (debug, info, warn, error)
- `component` (kernel, agent)
- `request_id` (for correlation)
- `message`
- `metadata` (context-specific fields)

### 6.3 Tracing

- OpenTelemetry support
- Spans for: External processing request, Agent call, Individual policy execution

## 7. Performance Requirements

| Metric | Target |
|--------|--------|
| P99 Latency | < 100ms (including policy execution) |
| Throughput | 10,000 requests/second per instance |
| Memory | < 1GB under load |
| CPU | 2 cores minimum |

## 8. Build and Deployment

### 8.1 Build Process

```bash
# Build Policy Kernel
cd policy-kernel
go build -o policy-kernel .

# Build Policy Agent (includes all policy implementations)
cd ../policy-agent
go build -o policy-agent .

# Build container image
docker build -t policy-engine:latest .
```

### 8.2 Container Image

See [deployment specification](policy-kernel/SPEC.md#deployment) for Dockerfile and supervisord configuration.

### 8.3 Health Checks

**Liveness Probe:**
- HTTP GET `/health/live` on metrics port (9090)
- Returns 200 if processes are running

**Readiness Probe:**
- HTTP GET `/health/ready` on metrics port (9090)
- Returns 200 if all configured agents are reachable and configuration is valid

## 9. Testing Strategy

### 9.1 Unit Tests

- Policy Kernel route selection logic
- Agent Core policy execution flow
- Individual policy implementations
- Context update logic
- Error handling paths

### 9.2 Integration Tests

- Kernel ↔ Agent communication over UDS
- Policy chain execution with context updates
- Timeout and retry behavior
- Configuration reload

### 9.3 E2E Tests

- Full Envoy → Kernel → Agent → Policies flow
- Multiple routes with different policy chains
- Failure scenarios (agent down, policy error)
- Performance under load

### 9.4 Performance Tests

- Benchmark policy execution latency
- Load test with 10K req/s
- Memory leak detection
- Resource limit validation

## 10. Future Enhancements

### 10.1 Potential Features

- **Policy Composition**: Allow policies to call other policies
- **Conditional Execution**: Skip policies based on conditions
- **Policy Caching**: Cache policy results based on request attributes

### 10.2 Scalability

- **Horizontal Scaling**: Multiple Policy Kernel instances
- **Multiple Agent Instances**: Run multiple policy-agent processes
- **Agent Specialization**: Different policy-agent binaries with different policy sets
- **Distributed Caching**: Shared cache across multiple containers

## 11. Glossary

- **Policy Kernel**: The main orchestrator component that interfaces with Envoy
- **Policy Agent**: The policy execution runtime containing agent core + policies
- **Agent Core**: The gRPC server and execution engine within a policy agent
- **Policy**: Individual enforcement logic module (e.g., authentication, rate limiting)
- **Route Name**: Identifier sent by Envoy to select policy chain
- **Instruction**: Action to be taken (modify headers, deny request, etc.)
- **Request Context**: Mutable state passed through policy chain
- **UDS**: Unix Domain Socket for inter-process communication
- **External Processing Filter**: Envoy extension point for custom request processing

---

## Document Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-11-02 | System | Split from v2.0 monolithic specification into component-based specs |
