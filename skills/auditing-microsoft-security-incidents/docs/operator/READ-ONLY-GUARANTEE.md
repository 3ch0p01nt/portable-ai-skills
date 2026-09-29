# Read-Only Guarantee

HAVOC is designed to avoid tenant-security-state mutation during approved acquisition. The guarantee is layered rather than based on trust in one script.

## Layers

- Pinned request policy and pinned cloud profile hashes.
- A separate guard process that evaluates every request before transport.
- Short-lived signed capabilities bound to operation, method, canonical path, structural query keys, API version, principal, source scope, and resource binding.
- Adapters for Graph, ARM, Log Analytics, Resource Graph, and Purview that call the guard before transport.
- Transport host allowlist from the selected cloud profile.
- Automatic redirects disabled; authorization is not forwarded across origins.
- Method restrictions: only approved GET and approved read-semantic POST query operations.
- Token checks for audience, issuer, tenant, and excess Graph scopes.
- Mutation scanning for KQL and pivot text before execution.
- Protected references for raw evidence instead of prompt-visible tenant data.

## What is allowed

Read-semantic POST operations are allowed only where the platform uses POST for query or retrieval-job semantics and the operation is explicitly present in the policy. Service-required retrieval-job state is bounded by the capability and provenance contract.

## What it does not guarantee

- RBAC excess privilege cannot be fully verified from the token.
- Platform availability varies by cloud; DoD mode records declared gaps from the pinned cloud profile.
- Missing telemetry is a coverage gap, not proof nothing happened.
- The tool cannot prove that external evidence, analyst notes, tickets, or enrichment are truthful.
- Human intent, business impact, legal conclusions, and HR attribution require separate authorized review.

All evidence is treated as untrusted input. Reports cite evidence and gaps; they do not grant authority to mutate tenant state.
