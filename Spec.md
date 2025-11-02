Policy engine specification

Policy engine is an implementation of external processing filter of Envoy Proxy (v1.36.2). Policy Engine is configured with a list of policies against the route name. This route name is sent from the Envoy Proxy. Based on the route name, the policy engine selects the appropriate policy list and executes them.

Policy engine has two parts.
1.  Policy Kernel: This is the gRPC server implementation of the external processing filter. It receives the request from Envoy Proxy and sends back the response (policy instructions). Kernel keeps the policies against route names, and picks the appropriate policies based on the route name received from Envoy Proxy. This keeps list of Policy Agents (against agent name) registered with it. It forwards the request to the appropriate Policy Agent and receives the response from it. Finally, it sends back the response to Envoy Proxy.
2.  Policy Agents:
    i.  Agent Core: Agent core is a gRPC server which receives the request from the Policy Kernel. This requests contains the list of policies to be executed with each policies meta data (eg: Policy: apiKeyAuth; Metadata: headerName). Agent core executes the policies one by one and sends back the response to the Policy Kernel. Response contains the list of instructions which will be evaluated at Policy Kernel. These instructions are as same as instructions to the Envoy Proxy. Agent core also acts as a registry for the policies. Agent core provides an interface for the policies to register themselves with it. In the request it sends policy meta data to the policies for execution. It also provides request context (eg: headers, body etc.,) to the policies for execution. It collects the instructions from each policy and sends back to the Policy Kernel. It also updated the request context based on the instructions from the policies. For example, if a policy sets a header, agent core updates the request context with the new header so that the subsequent policies can use it.
    ii.  Policy Implementations: These are the actual implementations of the policies. Agent core provides an interface for the policies to implement.
    
    Each policy is implemented as a separate module. Agent core and these policy implementations are compiled together to form a single binary called Policy Agent.

Policy Kernel and Policy Agents communicate using gRPC UDS (Unix Domain Sockets). These two components are deployed in the same Docker container.

Use Mermaid to draw diagrams if required.