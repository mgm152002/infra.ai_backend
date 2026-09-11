# Main Module Refactor Design

## Goal

Reduce `main.py` from roughly 6,000 lines to a small application composition module while preserving the current API paths, request models, authentication, response shapes, background workers, and business behavior.

## Current Problem

`main.py` currently combines application startup, middleware, route handlers, chat orchestration, knowledge-base logic, infrastructure automation, credential storage, and integration helpers. Several endpoint groups have already been copied into routers, but their original `@app` routes remain in `main.py`. Some routers also import functions back from `main.py`, so the existing split has not established a clean dependency boundary.

## Chosen Approach

Make `main.py` the composition root. It will create the FastAPI application, configure middleware, register routers, and connect the lifespan handler. Domain logic will move mostly verbatim into focused modules; this change will not redesign the business logic.

The dependency direction will be:

```text
main.py -> routers -> services -> core/integrations
```

Routers and services must not import `main.py`.

## Module Boundaries

### Application setup

- `main.py`: create the application, add middleware, and include routers.
- `app/core/lifespan.py`: start escalation, incident, and asynchronous chat workers.

### Knowledge base

- `app/services/knowledge_service.py`: Pinecone index access, embedding, chunking, document storage, document deletion support, and knowledge queries.
- `app/api/routers/knowledge.py`: `/addKnowledge`, `/getKnowledge`, and `/knowledge/*` endpoints.

### Infrastructure automation and chat

- `app/services/automation_service.py`: AWS, SSH, ServiceNow, CMDB lookup, incident lookup, external integration tools, and the tool registry used by the agent.
- `app/services/chat_service.py`: chat request orchestration, history persistence, async-job persistence, and the chat worker loop.
- `app/api/routers/chat.py`: remain the owner of `/chat*` endpoints and call `chat_service` directly instead of importing `main.py`.
- `app/services/incident_service.py`: import infrastructure automation from `automation_service` instead of `main.py`.

### Credentials and remaining operations

- `app/api/routers/credentials.py`: existing AWS, SSH, ServiceNow, Slack, and email credential endpoints.
- `app/api/routers/operations.py`: legacy queue, diagnostic, planning, result, RCA, job-status, and health endpoints that do not belong to an existing router.

### Existing routers

The existing `cmdb`, `incidents`, `integrations_config`, `workflow`, `admin`, and `sse` routers remain the single route owners for their domains. Shadowed duplicate `@app` handlers will be removed after verifying that their effective method/path pairs are already registered by these routers. Shared helpers still used by another module will be moved before their old definitions are removed.

## Behavior Preservation

- Keep every externally reachable HTTP method and path.
- Keep existing router prefixes and registration order where route matching depends on order.
- Keep request schemas, dependency injection, permission checks, status codes, and response models unchanged.
- Move implementations verbatim except for imports and references required to remove `main.py` dependencies.
- Do not rename public functions that tests or other modules import unless compatibility aliases are required.
- Do not modify database queries, external integration behavior, prompts, worker counts, or queue names.
- Do not add new dependencies.

## Testing

Before extraction, add structural tests that fail while `main.py` still owns routes or remains oversized. Preserve the existing integration tests as the behavior regression suite. Add focused tests for route ownership and for the removal of imports from `main.py`.

Verification will include:

- Complete `pytest` suite.
- Ruff formatting and lint checks for changed files.
- `git diff --check`.
- A method/path inventory comparison to confirm that all externally reachable routes remain registered.
- Importing `main.app` to catch circular imports and startup-time errors.

## Success Criteria

- `main.py` contains application composition only and no `@app` endpoint decorators.
- `main.py` is under 300 lines.
- No file under `app/` imports `main.py`.
- All currently reachable API method/path pairs remain available.
- The full existing test suite passes.

## Non-Goals

- Rewriting endpoint behavior or database access patterns.
- Redesigning the large incident service.
- Renaming legacy endpoints or schemas.
- Fixing unrelated style, security, or deprecation issues.
