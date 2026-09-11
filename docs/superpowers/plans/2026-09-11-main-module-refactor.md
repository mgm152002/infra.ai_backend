# Main Module Refactor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn `main.py` into a sub-300-line FastAPI composition module without changing the application’s reachable HTTP contract or business behavior.

**Architecture:** Extract cohesive knowledge, infrastructure-tooling, chat, credential, and operational responsibilities into routers and services. Preserve the dependency direction `main.py -> routers -> services -> core/integrations`, eliminate every import of `main.py` from `app/`, and remove shadowed direct routes after their owning routers are verified.

**Tech Stack:** Python 3.11+, FastAPI, Pydantic, Supabase, LangChain, Pinecone, Redis, boto3, pytest, Ruff

**Spec:** `docs/superpowers/specs/2026-09-11-main-module-refactor-design.md`

## Global Constraints

- Keep every externally reachable HTTP method and path.
- Keep existing router prefixes and registration order where route matching depends on order.
- Keep request schemas, dependency injection, permission checks, status codes, and response models unchanged.
- Move implementations verbatim except for imports and references required to remove `main.py` dependencies.
- Do not modify database queries, external integration behavior, prompts, worker counts, or queue names.
- Do not add new dependencies.
- Do not redesign `app/services/incident_service.py` beyond replacing its dynamic `main.py` import.

## Target File Structure

- `main.py`: FastAPI instance, middleware, lifespan binding, and router registration only.
- `app/core/lifespan.py`: escalation monitor and incident/chat worker startup.
- `app/services/knowledge_service.py`: Pinecone-backed document and query operations.
- `app/api/routers/knowledge.py`: knowledge HTTP endpoints.
- `app/services/infrastructure_automation.py`: AWS/SSH/ServiceNow/CMDB/incident automation functions.
- `app/services/agent_tools.py`: external integration tools, LangChain tool collection, and tool registry.
- `app/services/chat_service.py`: shared chat execution, Redis state, history, and worker loop.
- `app/api/routers/chat.py`: chat transport endpoints only.
- `app/api/routers/credentials.py`: AWS, SSH, ServiceNow, Slack, email, and JWT credential routes.
- `app/api/routers/operations.py`: queue, diagnostic, web-search, planning, result, RCA, and job routes.
- `app/api/routers/cmdb.py`: existing CMDB routes plus `/uploadCMDB`.
- `app/api/routers/workflow.py`: prefixed workflow routes and a separate unprefixed `legacy_router`.
- `app/api/routers/admin.py`: prefixed admin routes and a separate unprefixed `legacy_router`.

---

### Task 1: Characterize the Existing HTTP Contract

**Files:**
- Create: `tests/route_contract.py`
- Create: `tests/fixtures/route_contract.json`
- Create: `tests/unit/test_route_contract.py`

**Interfaces:**
- Consumes: `main.app` and its generated OpenAPI schema.
- Produces: `collect_route_contract(app) -> set[tuple[str, str]]`, used before and after extraction to compare documented HTTP method/path pairs.

- [ ] **Step 1: Add the route-contract collector**

```python
# tests/route_contract.py
def collect_route_contract(app):
    return {
        (path, method.upper())
        for path, operations in app.openapi()["paths"].items()
        for method in operations
        if method.lower() in {"get", "post", "put", "patch", "delete", "options", "head"}
    }
```

- [ ] **Step 2: Capture the complete pre-refactor contract**

Run this read-only command and copy its JSON output into `tests/fixtures/route_contract.json` with `apply_patch`:

```bash
python -c 'import json; from main import app; from tests.route_contract import collect_route_contract; print(json.dumps(sorted(collect_route_contract(app)), indent=2))'
```

- [ ] **Step 3: Add the characterization test**

```python
# tests/unit/test_route_contract.py
import json
from pathlib import Path


def test_main_exposes_required_route_contract():
    from main import app
    from tests.route_contract import collect_route_contract

    contract = collect_route_contract(app)
    expected = {
        tuple(item)
        for item in json.loads(Path("tests/fixtures/route_contract.json").read_text())
    }
    required = {
        ("/chat", "POST"),
        ("/chat/stream", "POST"),
        ("/cmdb", "GET"),
        ("/uploadCMDB", "POST"),
        ("/incidentAdd", "POST"),
        ("/incidents/all", "GET"),
        ("/alert-types", "GET"),
        ("/pending-actions", "GET"),
        ("/admin/health", "GET"),
        ("/worker/queue-health", "GET"),
        ("/addKnowledge", "POST"),
        ("/getKnowledge", "GET"),
    }
    assert required <= contract
    assert contract == expected
```

- [ ] **Step 4: Run the characterization test**

Run: `pytest tests/unit/test_route_contract.py -v`

Expected: PASS against the current application and establish the contract guard before moving code.

- [ ] **Step 5: Commit the characterization test**

```bash
git add tests/route_contract.py tests/fixtures/route_contract.json tests/unit/test_route_contract.py
git commit -m "test: characterize application route contract"
```

---

### Task 2: Extract the Knowledge Subsystem

**Files:**
- Create: `app/services/knowledge_service.py`
- Create: `app/api/routers/knowledge.py`
- Modify: `main.py:796-1465`
- Create: `tests/unit/test_knowledge_router.py`

**Interfaces:**
- Produces from `knowledge_service`: `query_knowledge_base`, `store_document_in_kb`, `store_architecture_in_kb`, `extract_text_from_upload`, `list_documents`, and `delete_document`.
- Produces from `knowledge.router`: `/addKnowledge`, `/knowledge/architecture`, `/knowledge/architecture/docs`, `/getKnowledge`, `/knowledge/docs`, and `/knowledge/{doc_id}`.
- Consumes: `app.core.database.supabase`, `app.core.llm.call_llm`, Pinecone, OpenAI embeddings, and `verify_token`.

- [ ] **Step 1: Write a failing router ownership test**

```python
def test_knowledge_router_owns_all_knowledge_paths():
    from app.api.routers.knowledge import router

    paths = {route.path for route in router.routes}
    assert paths == {
        "/addKnowledge",
        "/knowledge/architecture",
        "/knowledge/architecture/docs",
        "/getKnowledge",
        "/knowledge/docs",
        "/knowledge/{doc_id}",
    }
```

- [ ] **Step 2: Verify the test fails because the module is absent**

Run: `pytest tests/unit/test_knowledge_router.py -v`

Expected: FAIL with `ModuleNotFoundError: app.api.routers.knowledge`.

- [ ] **Step 3: Move knowledge implementation into the service and router**

Move `_get_architecture_kb_text`, `_get_kb_index`, `_embed_texts`, `_chunk_text`, `query_knowledge_base`, `store_document_in_kb`, `store_architecture_in_kb`, and `_extract_text_from_upload` from `main.py` into `knowledge_service.py`. Rename only `_extract_text_from_upload` to the exported `extract_text_from_upload`. Move the six associated handlers into `knowledge.py`, replace `@app` with `@router`, and import service functions directly:

```python
from fastapi import APIRouter

from app.services.knowledge_service import (
    delete_document,
    extract_text_from_upload,
    list_documents,
    query_knowledge_base,
    store_architecture_in_kb,
    store_document_in_kb,
)

router = APIRouter()
```

Keep token decoding, Supabase filters, exception handling, response dictionaries, and status codes identical to the current handlers.

- [ ] **Step 4: Register the router and run knowledge plus route tests**

```python
from app.api.routers import knowledge

app.include_router(knowledge.router, tags=["Knowledge"])
```

Run: `pytest tests/unit/test_knowledge_router.py tests/unit/test_route_contract.py -v`

Expected: PASS.

- [ ] **Step 5: Commit the knowledge extraction**

```bash
git add app/services/knowledge_service.py app/api/routers/knowledge.py main.py tests/unit/test_knowledge_router.py
git commit -m "refactor: extract knowledge subsystem"
```

---

### Task 3: Extract Infrastructure Automation and Agent Tools

**Files:**
- Create: `app/services/infrastructure_automation.py`
- Create: `app/services/agent_tools.py`
- Modify: `app/services/incident_service.py:2240-2245`
- Modify: `main.py:543-795`
- Modify: `main.py:2024-3496`
- Create: `tests/services/test_agent_tools_structure.py`

**Interfaces:**
- Produces from `infrastructure_automation`: `send_escalation_email`, `power_status_tool`, `selfHealing`, `execute_command`, `send_mail_to_l2_engineer`, `create_incident`, `update_incident`, `get_incident_details`, `list_local_incidents`, `get_local_incident_details`, `update_local_incident`, `get_local_cmdb_count`, `search_local_cmdb`, `get_local_cmdb_item`, `getfromcmdb`, `search_cmdb`, and `infra_automation_ai`.
- Produces from `agent_tools`: `CHAT_SYSTEM_PROMPT`, `llm_with_tools`, `tool_mapping`, `TOOLS_REQUIRING_MAIL`, and every decorated external integration tool currently registered in `main.py`.
- Consumes: `knowledge_service.query_knowledge_base`, `app.core.llm`, `app.core.database`, `integrations.*`, boto3, Paramiko, and LangChain.

- [ ] **Step 1: Write failing dependency-direction tests**

```python
from pathlib import Path


def test_agent_tools_exports_chat_registry():
    from app.services.agent_tools import (
        CHAT_SYSTEM_PROMPT,
        TOOLS_REQUIRING_MAIL,
        llm_with_tools,
        tool_mapping,
    )

    assert CHAT_SYSTEM_PROMPT
    assert isinstance(TOOLS_REQUIRING_MAIL, set)
    assert llm_with_tools is not None
    assert tool_mapping


def test_incident_service_does_not_import_main():
    source = Path("app/services/incident_service.py").read_text()
    assert "from main import" not in source
```

- [ ] **Step 2: Verify the tests fail for the missing module and current dynamic import**

Run: `pytest tests/services/test_agent_tools_structure.py -v`

Expected: FAIL because `agent_tools.py` does not exist and `incident_service.py` contains `from main import infra_automation_ai`.

- [ ] **Step 3: Move the infrastructure functions verbatim**

Move the listed infrastructure functions and their required constants/imports into `infrastructure_automation.py`. Keep function signatures and decorator metadata unchanged. Replace the incident service’s dynamic import with:

```python
from app.services.infrastructure_automation import infra_automation_ai as _infra_automation_ai
```

- [ ] **Step 4: Move the external tools and registry verbatim**

Move `ask_knowledge_base`, Prometheus, GitHub, GitHub MCP, Jira, Confluence, PagerDuty, web-search, RCA, and problem-record tools into `agent_tools.py`. Import local infrastructure tools from `infrastructure_automation` and knowledge lookup from `knowledge_service`. Preserve the current tool list order, lowercase mapping, and mail-injection set:

```python
llm_with_tools = tool_llm.bind_tools(tools)
tool_mapping = {tool.name.lower(): tool for tool in tools}
```

- [ ] **Step 5: Run focused service and incident tests**

Run: `pytest tests/services/test_agent_tools_structure.py tests/services/test_incident_service.py -v`

Expected: PASS.

- [ ] **Step 6: Commit the tool extraction**

```bash
git add app/services/infrastructure_automation.py app/services/agent_tools.py app/services/incident_service.py main.py tests/services/test_agent_tools_structure.py
git commit -m "refactor: extract infrastructure and agent tools"
```

---

### Task 4: Extract Chat Orchestration and Remove the Circular Import

**Files:**
- Create: `app/services/chat_service.py`
- Modify: `app/api/routers/chat.py`
- Modify: `main.py:3497-4098`
- Create: `tests/services/test_chat_service_structure.py`

**Interfaces:**
- Produces: `process_chat_request`, `chat_worker_loop`, `chat_job_redis_key`, `store_chat_history`, `get_chat_job`, and `enqueue_chat_job`.
- Consumes: `agent_tools.CHAT_SYSTEM_PROMPT`, `agent_tools.llm_with_tools`, `agent_tools.tool_mapping`, `agent_tools.TOOLS_REQUIRING_MAIL`, Redis, SQS, Supabase, and `app.core.llm.call_llm`.
- `chat.router` consumes only `chat_service` and shared schemas/security.

- [ ] **Step 1: Write failing structure tests**

```python
from pathlib import Path


def test_chat_service_exports_worker_and_request_processor():
    from app.services.chat_service import chat_worker_loop, process_chat_request

    assert callable(chat_worker_loop)
    assert callable(process_chat_request)


def test_chat_router_does_not_import_main():
    source = Path("app/api/routers/chat.py").read_text()
    assert "from main import" not in source
```

- [ ] **Step 2: Verify the tests fail**

Run: `pytest tests/services/test_chat_service_structure.py -v`

Expected: FAIL because `chat_service.py` is absent and `chat.py` imports `main.py`.

- [ ] **Step 3: Move chat orchestration into the service**

Move `_chat_job_redis_key`, `_store_chat_history`, `process_chat_request`, and `chat_worker_loop` into `chat_service.py`, retaining Redis key format, TTL, SQS queue name, retry behavior, tool-call loop, history payload, and result format. Export non-underscored names for router use while retaining aliases for compatibility:

```python
chat_job_redis_key = _chat_job_redis_key
store_chat_history = _store_chat_history
```

- [ ] **Step 4: Make the router call the service directly**

Replace both runtime imports from `main.py` with module imports from `app.services.chat_service` and `app.services.agent_tools`. Keep all `/chat*` decorators, authentication, streaming event shapes, and Supabase session queries unchanged.

- [ ] **Step 5: Run chat tests**

Run: `pytest tests/services/test_chat_service_structure.py tests/integration/test_chat.py -v`

Expected: PASS.

- [ ] **Step 6: Commit the chat extraction**

```bash
git add app/services/chat_service.py app/api/routers/chat.py main.py tests/services/test_chat_service_structure.py
git commit -m "refactor: extract chat orchestration"
```

---

### Task 5: Extract Credential Routes

**Files:**
- Create: `app/api/routers/credentials.py`
- Modify: `main.py:1509-2019`
- Modify: `main.py:4176-4391`
- Modify: `main.py:4645-4819`
- Create: `tests/integration/test_credentials.py`

**Interfaces:**
- Produces: a single `router` containing `/uploadSSH`, `/getSnowKey/{mail}`, `/getSSHKeys/{mail}`, `/getAwsKeys/{mail}`, `/addSNOWCredentials`, `/addAwsCredentials`, `/updateSSH`, `/updateServiceNow`, `/prometheus/config`, `/addSlackCredentials`, `/getSlackCredentials/{mail}`, `/addEmailCredentials`, `/getEmailCredentials/{mail}`, and `/storeJwt/{jwt}`.
- Consumes: credential schemas, `verify_token`, `HTTPBearer`, Clerk JWT verification, Supabase, Infisical `get_many`/`set_many`, and Slack configuration.

- [ ] **Step 1: Write a failing credential-route ownership test**

```python
def test_credentials_router_owns_legacy_credential_paths():
    from app.api.routers.credentials import router

    paths = {route.path for route in router.routes}
    assert "/uploadSSH" in paths
    assert "/getAwsKeys/{mail}" in paths
    assert "/addAwsCredentials" in paths
    assert "/updateServiceNow" in paths
    assert "/addSlackCredentials" in paths
    assert "/addEmailCredentials" in paths
```

- [ ] **Step 2: Verify the test fails because the router is absent**

Run: `pytest tests/integration/test_credentials.py -v`

Expected: FAIL with `ModuleNotFoundError: app.api.routers.credentials`.

- [ ] **Step 3: Move handlers and credential helpers into the router**

Copy the effective, first-registered implementation for duplicate legacy paths such as `/addSNOWCredentials`. Replace `@app` with `@router`; preserve decorator arguments, authentication, Infisical key names, response bodies, and exception handling. Do not move the already-owned `/integrations/*` routes from `integrations_config.py`.

- [ ] **Step 4: Register the router and run focused tests**

```python
from app.api.routers import credentials

app.include_router(credentials.router, tags=["Credentials"])
```

Run: `pytest tests/integration/test_credentials.py tests/unit/test_route_contract.py -v`

Expected: PASS.

- [ ] **Step 5: Commit credential extraction**

```bash
git add app/api/routers/credentials.py main.py tests/integration/test_credentials.py
git commit -m "refactor: extract credential routes"
```

---

### Task 6: Assign Every Remaining Route to a Router

**Files:**
- Create: `app/api/routers/operations.py`
- Modify: `app/api/routers/cmdb.py`
- Modify: `app/api/routers/workflow.py`
- Modify: `app/api/routers/admin.py`
- Modify: `main.py:1467-1508`
- Modify: `main.py:3332-3339`
- Modify: `main.py:4101-4174`
- Modify: `main.py:4835-6004`
- Create: `tests/unit/test_router_ownership.py`

**Interfaces:**
- `operations.router` produces queue, diagnostic, web-search, plan, result, RCA, and job-status paths.
- `cmdb.router` additionally produces `POST /uploadCMDB`.
- `workflow.legacy_router` produces unprefixed alert type, escalation rule, alert-type escalation, and pending-action paths.
- `admin.legacy_router` produces `/admin/users`, `/admin/health`, and `/worker/queue-health`.
- Existing incident and integration routers remain the owners of their already-included unprefixed paths.

- [ ] **Step 1: Write failing ownership tests**

```python
def test_remaining_routes_have_domain_owners():
    from app.api.routers import admin, cmdb, operations, workflow

    operation_paths = {route.path for route in operations.router.routes}
    cmdb_paths = {route.path for route in cmdb.router.routes}
    workflow_paths = {route.path for route in workflow.legacy_router.routes}
    admin_paths = {route.path for route in admin.legacy_router.routes}

    assert {"/queueAdd", "/queueRemove", "/websearch", "/plan"} <= operation_paths
    assert "/uploadCMDB" in cmdb_paths
    assert {"/alert-types", "/escalation-rules", "/pending-actions"} <= workflow_paths
    assert {"/admin/users", "/admin/health", "/worker/queue-health"} <= admin_paths
```

- [ ] **Step 2: Verify the test fails for missing router ownership**

Run: `pytest tests/unit/test_router_ownership.py -v`

Expected: FAIL because `operations.py` and both `legacy_router` objects are absent.

- [ ] **Step 3: Move uniquely owned routes**

Create `operations.router`, append `/uploadCMDB` to `cmdb.router`, and add `legacy_router = APIRouter()` to both `workflow.py` and `admin.py`. Move handlers with their current decorators changed only from `@app` to the appropriate router object.

- [ ] **Step 4: Remove shadowed duplicates**

Delete direct handlers whose method/path pairs are already registered earlier by `chat.router`, `incidents.router`, or `integrations_config.router`. Before deleting each block, use `rg` to confirm its helper names are either local to the duplicate block or exported from the new service modules. Retain the behavior of the first route registered in the current app.

- [ ] **Step 5: Register new and legacy routers in current route order**

```python
app.include_router(operations.router, tags=["Operations"])
app.include_router(workflow.legacy_router, tags=["Workflow"])
app.include_router(admin.legacy_router, tags=["Admin"])
```

- [ ] **Step 6: Run all integration tests**

Run: `pytest tests/integration tests/unit/test_router_ownership.py tests/unit/test_route_contract.py -v`

Expected: PASS.

- [ ] **Step 7: Commit route ownership cleanup**

```bash
git add app/api/routers/operations.py app/api/routers/cmdb.py app/api/routers/workflow.py app/api/routers/admin.py main.py tests/unit/test_router_ownership.py
git commit -m "refactor: assign routes to domain routers"
```

---

### Task 7: Extract Lifespan and Reduce `main.py` to Composition

**Files:**
- Create: `app/core/lifespan.py`
- Rewrite: `main.py`
- Create: `tests/unit/test_main_structure.py`

**Interfaces:**
- Produces: `worker_lifespan(app: FastAPI)` from `app.core.lifespan`.
- `main.py` continues to export `app` for ASGI servers and tests.
- Consumes: all router objects, `RequestLoggingMiddleware`, `CORSMiddleware`, and `worker_lifespan`.

- [ ] **Step 1: Write failing composition tests**

```python
from pathlib import Path


def test_main_is_only_application_composition():
    source = Path("main.py").read_text()
    assert len(source.splitlines()) < 300
    assert "@app." not in source


def test_app_modules_do_not_import_main():
    offenders = []
    for path in Path("app").rglob("*.py"):
        if "from main import" in path.read_text() or "import main" in path.read_text():
            offenders.append(str(path))
    assert offenders == []
```

- [ ] **Step 2: Verify the tests fail for the current entrypoint**

Run: `pytest tests/unit/test_main_structure.py -v`

Expected: FAIL because `main.py` exceeds 300 lines and still owns direct routes.

- [ ] **Step 3: Move worker startup to the lifespan module**

Move `worker_lifespan` into `app/core/lifespan.py`. Import `worker.worker_loop`, `chat_service.chat_worker_loop`, `EscalationService`, settings, and logger directly. Preserve worker caps, queue-collision protection, daemon thread names, and `app.state.worker_threads`.

- [ ] **Step 4: Rewrite `main.py` as the composition root**

Retain only this structure, with the complete existing router list and existing CORS values:

```python
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routers import (
    admin,
    chat,
    cmdb,
    credentials,
    incidents,
    integrations_config,
    knowledge,
    operations,
    sse,
    workflow,
)
from app.core.lifespan import worker_lifespan
from app.core.middleware import RequestLoggingMiddleware

app = FastAPI(lifespan=worker_lifespan)
app.add_middleware(RequestLoggingMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

Register prefixed and unprefixed routers in the preserved order below that block. Keep `app` as the only public entrypoint object.

- [ ] **Step 5: Run structure and full route tests**

Run: `pytest tests/unit/test_main_structure.py tests/unit/test_route_contract.py tests/integration -v`

Expected: PASS.

- [ ] **Step 6: Commit the composition root**

```bash
git add app/core/lifespan.py main.py tests/unit/test_main_structure.py
git commit -m "refactor: make main an application composition module"
```

---

### Task 8: Final Verification and Pull Request Update

**Files:**
- Modify only files required by failures directly caused by Tasks 1-7.

**Interfaces:**
- Consumes: completed refactor.
- Produces: verified branch with no behavior or route-contract regressions.

- [ ] **Step 1: Run the complete test suite**

Run: `pytest -q`

Expected: all tests pass; only existing third-party deprecation warnings are permitted.

- [ ] **Step 2: Run formatting and focused lint checks**

Run: `ruff format --check main.py app/core/lifespan.py app/services/knowledge_service.py app/services/infrastructure_automation.py app/services/agent_tools.py app/services/chat_service.py app/services/incident_service.py app/api/routers/knowledge.py app/api/routers/chat.py app/api/routers/credentials.py app/api/routers/operations.py app/api/routers/cmdb.py app/api/routers/workflow.py app/api/routers/admin.py tests/route_contract.py tests/unit/test_route_contract.py tests/unit/test_knowledge_router.py tests/services/test_agent_tools_structure.py tests/services/test_chat_service_structure.py tests/integration/test_credentials.py tests/unit/test_router_ownership.py tests/unit/test_main_structure.py`

Run: `ruff check main.py app/core/lifespan.py app/services/knowledge_service.py app/services/infrastructure_automation.py app/services/agent_tools.py app/services/chat_service.py app/services/incident_service.py app/api/routers/knowledge.py app/api/routers/chat.py app/api/routers/credentials.py app/api/routers/operations.py app/api/routers/cmdb.py app/api/routers/workflow.py app/api/routers/admin.py tests/route_contract.py tests/unit/test_route_contract.py tests/unit/test_knowledge_router.py tests/services/test_agent_tools_structure.py tests/services/test_chat_service_structure.py tests/integration/test_credentials.py tests/unit/test_router_ownership.py tests/unit/test_main_structure.py`

Expected: all changed files pass formatting and lint checks.

- [ ] **Step 3: Verify structure, imports, and whitespace**

Run: `wc -l main.py`

Expected: fewer than 300 lines.

Run: `rg -n 'from main import|import main' app`

Expected: no matches.

Run: `git diff --check`

Expected: no output and exit code 0.

- [ ] **Step 4: Inspect and commit any verification-only corrections**

```bash
git status --short
git diff --check
```

If verification requires a correction, stage only the corrected file paths shown by `git status --short` and commit them with `git commit -m "test: verify modular application composition"`. Skip this commit when verification requires no corrections.

- [ ] **Step 5: Push the branch and confirm the pull-request check**

```bash
git push origin refactor/issue-14-main-modules
gh pr checks 15 --repo mgm152002/infra.ai_backend --watch
```

Expected: PR #15 reports a successful `Lint and test` check.
