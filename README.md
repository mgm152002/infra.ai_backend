# Infra AI Backend

## Overview
Infra AI Backend is a FastAPI-based automation platform for incident management, infrastructure operations, and CMDB/knowledge-base management. It integrates:

- **Supabase** – primary data store for users, incidents, CMDB, results, knowledge docs, Prometheus configs, and chat history
- **AWS** – SQS (incident & chat queues), EC2 (targets), ECS Fargate (Ansible sandbox), S3 & CloudWatch Logs
- **Pinecone** – vector knowledge base for SOPs/runbooks
- **OpenRouter LLMs** – core reasoning engine (chat, diagnostics, automation, ServiceNow helper)
- **Infisical** – secret management for per-user AWS, SSH, and ServiceNow credentials
- **Redis** – async chat job state and JWT handoff for SSH
- **Prometheus** – optional metrics context to guide diagnostics
- **ServiceNow** – incident integration (create/update/fetch)

The backend exposes both synchronous HTTP APIs and long-running background workers for self-healing incident resolution.

---

## High-Level Architecture

### Logical components

1. **HTTP API service (FastAPI)**
   - Main entrypoint: `main.py`
   - Provides REST endpoints for:
     - Chat and infra automation
     - Incident creation and listing
     - CMDB CRUD
     - Knowledge-base ingestion & search
     - Credential management (AWS, SSH, ServiceNow)
     - Prometheus datasource config
     - Results and analytics
   - Starts in-process worker threads for:
     - SQS incident worker (`worker_loop` from `worker.py`)
     - SQS async chat worker (`chat_worker_loop` in `main.py`)

2. **Incident worker service**
   - Core implementation: `worker.py`
   - Polls an AWS SQS FIFO queue for incident jobs
   - Looks up CMDB and user context in Supabase
   - Fetches SSH keys and credentials from Infisical
   - Optionally enriches with Pinecone KB and Prometheus metrics
   - Uses OpenRouter LLMs to:
     - Generate a diagnostic plan
     - Execute diagnostics on the target host via SSH
     - Analyze diagnostics to determine root cause and resolution steps
     - Execute resolution commands on the host
   - Updates Incidents and Results tables in Supabase
   - Writes detailed structured logs to `infra_worker.log`

3. **Ansible automation sandbox**
   - Script: `ansible_sandbox.py`
   - Used indirectly by the `infra_automation_ai` tool in `main.py`
   - Flow:
     - The HTTP API asks the LLM to generate:
       - Ansible module installation shell script
       - Inventory file
       - Playbook YAML
       - Playbook run command
     - Backend writes these artifacts plus AWS vars and SSH key to local disk
     - `ansible_sandbox.py` uploads artifacts to S3 and launches an ECS Fargate task using an Ansible runner image
     - The task pulls artifacts from S3, runs the playbook, and streams logs to CloudWatch Logs
     - Sandbox output is collected and summarized back to the user

4. **Chat + tools orchestration**
   - Synchronous `/chat` endpoint
   - Async `/chat/async` endpoint + `Chatqueue` SQS + Redis job storage
   - Uses LangChain tools to call:
     - ServiceNow (create/update/get incident)
     - CMDB lookup
     - Knowledge base search (`ask_knowledge_base`)
     - Infra automation (`infra_automation_ai` → Ansible sandbox)
   - Chat history persisted in Supabase

---

## Data & Control Flows

### 1. Incident auto-remediation pipeline

1. **Incident creation**
   - Frontend calls `POST /incidentAdd` on `main.py`.
   - Backend inserts a row into the `Incidents` table with `user_id`, `tag_id`, `state`, and `inc_number`.
   - The same request enqueues a message into the AWS SQS FIFO queue `infraaiqueue.fifo` with:
     - Minimal AWS stub config (access/secret/region left blank; real values are fetched later via Infisical)
     - Incident meta: incident number, subject, message
     - Meta block: `user_id` and `tag_id` for CMDB lookup

2. **Incident queue consumption**
   - The incident worker (`worker_loop` in `worker.py`) runs either:
     - As a standalone process: `python worker.py`, **or**
     - As background threads started by FastAPI lifespan (`worker_lifespan` in `main.py`).
   - Worker polls `infraaiqueue.fifo`, extends message visibility, and calls `process_incident`.

3. **Context enrichment** (`process_incident`)
   - CMDB lookup in Supabase:
     - Primary: `Meta.tag_id` (and optional `Meta.user_id`)
     - Fallback: `Aws.instance_id` as `tag_id`
   - User resolution: fetch owner `user_id` from CMDB row, then `email` from `Users` table.
   - SSH key retrieval via Infisical:
     - Secret name pattern: `SSH_KEY_{email}`
     - Key written to `key.pem` with `0600` permissions.
   - Knowledge base context:
     - Queries Pinecone using incident `inc_number`, subject, message.
     - Combines matched SOP/runbook chunks into `combined_context`.
   - Prometheus metrics (optional, per user):
     - If a `PrometheusConfigs` row exists for the user, worker calls the Prometheus HTTP API for the host (node_exporter-style `ip:9100` target).
     - Queries include availability (`up`), CPU usage, load, and memory pressure.

4. **Diagnostics generation & execution**
   - Worker builds a prompt combining:
     - Incident description
     - CMDB host info (OS, IP)
     - KB context (if any)
     - Prometheus metrics JSON (if any)
   - OpenRouter LLM returns a JSON plan of `todos` with:
     - `step` – human-readable description
     - `command` – non-interactive command to run on the host
     - `expected_output` – what the command should reveal
   - Worker connects to the host via SSH (`paramiko`) using `key.pem` and runs each command.
   - Output is verified heuristically for obvious errors.

5. **Root-cause analysis & resolution**
   - Diagnostics results are serialized and sent to OpenRouter again for analysis.
   - LLM responds with:
     - `root_cause`
     - `resolution_steps[]`
     - `verification`
   - For each `resolution_step`, worker:
     - Generates a concrete non-interactive command via LLM
     - Executes it over SSH on the host
   - Overall status is:
     - `Resolved` if all steps succeed
     - `Partially Resolved` if any step fails
     - `Error` if prerequisites (CMDB, user, SSH key, etc.) are missing

6. **Persistence and logging**
   - `Incidents` table:
     - `state` is updated to `Resolved`, `Partially Resolved`, or `Error`
     - `solution` JSON stores root cause, resolution steps, and KB metadata
   - `Results` table:
     - Full diagnostics, analysis, and resolution objects are stored in `description`
     - A short root-cause summary is stored in `short_description`
   - Logs:
     - Detailed structured logs written to `infra_worker.log` with per-incident and per-host prefixes
     - SSH private keys are never logged (optionally redacted)

### 2. Chat and tool orchestration

1. **Synchronous chat (`POST /chat`)**
   - JWT is validated using a public key and Supabase `Users` table.
   - The system prompt enforces:
     - Always call `ask_knowledge_base` first.
     - For any infra-like request, call `infra_automation_ai` after KB lookup.
     - Never ask user for internal identifiers like email; backend injects them.
   - Tools available to the model:
     - `create_incident`, `update_incident`, `get_incident_details` (ServiceNow)
     - `getfromcmdb` (Supabase CMDB)
     - `infra_automation_ai` (Ansible-based automation)
     - `ask_knowledge_base` (Pinecone KB)
   - Tool traces and final result are stored in Supabase `ChatHistory`.

2. **Async chat (`POST /chat/async`)**
   - Request is enqueued into SQS `Chatqueue` with a `job_id`.
   - Job state is initialized in Redis (`chat:job:{job_id}`).
   - Background `chat_worker_loop` (spawned in `main.py`) polls `Chatqueue`, processes jobs with `process_chat_request`, and writes the result back to Redis.
   - Client polls `GET /chat/async/{job_id}` to fetch status and final result.

3. **Web search augmentation (`POST /websearch`)**
   - Uses Tavily search to pull a small set of URLs.
   - Scrapes HTML with `requests` + BeautifulSoup, truncates content, and lets OpenRouter LLM synthesize an answer.

### 3. Ansible-based infra automation

1. Chat or a backend call invokes `infra_automation_ai` with natural-language infra instructions.
2. OpenRouter LLM is instructed to return **only** four tagged sections:
   - `<shell_commands>` – non-interactive commands to install any required Ansible collections/modules
   - `<inventory_file>` – Ansible inventory content (or empty if not needed)
   - `<playbook>` – complete playbook YAML
   - `<playbook_run_command>` – exact command to run the playbook using `inventory_file.ini` and `playbook.yml`
3. Backend writes these to:
   - `install_ansible_modules.sh`
   - `inventory_file.ini`
   - `playbook.yml`
   - `playbook_command.sh`
   - `vars.yml` (with AWS credentials from Infisical)
   - `key.pem` (SSH key from Infisical)
4. `ansible_sandbox.py`:
   - Uploads all artifacts to S3 under `ansible-runtime/`
   - Registers or reuses an ECS Fargate task definition for an Ansible runner image built from `Dockerfiles/Dockerfile`
   - Ensures an ECS cluster exists and launches a task in the default VPC
   - Streams Ansible output via CloudWatch Logs
   - Cleans up S3 artifacts afterward
5. Backend summarizes the CloudWatch Logs output and returns a user-friendly explanation (with Ansible/noisy boilerplate filtered out).

---

## Key Files & Modules

- **FastAPI application & HTTP APIs**
  - `main.py` – primary FastAPI app, routes, chat orchestration, CMDB/KB/credentials/Prometheus endpoints, async chat workers, and infra automation tools.

- **Incident worker**
  - `worker.py` – long-running worker that consumes `infraaiqueue.fifo`, executes diagnostics and resolutions over SSH, updates Supabase, and logs to `infra_worker.log`.

- **Ansible sandbox / ECS runner**
  - `ansible_sandbox.py` – uploads runtime files to S3, runs an ECS Fargate task with an Ansible runner image, fetches CloudWatch Logs, and cleans up S3.
  - `Dockerfiles/Dockerfile` – image used as the Ansible execution environment (Python 3.11, Ansible, AWS CLI, non-root `ansible` user, sandboxed `ansible-playbook` entrypoint).

- **Containerization for API**
  - `Dockerfile` – builds the FastAPI app image and starts the dev server.

- **Python dependencies**
  - `requirements.txt` – Python packages for FastAPI, LLMs, Pinecone, Supabase, Redis, Prometheus client, and other integrations.

---

## Supabase Data Model (expected tables)

The backend assumes the following (non-exhaustive) tables exist in Supabase:

- `Users` – users (at minimum: `id`, `email`)
- `Incidents` – incidents linked to users and CMDB entries, with `state` and optional `solution` JSON
- `CMDB` – configuration items / hosts, including `tag_id`, `ip`, `os`, `type`, `description`, `user_id`
- `Results` – detailed incident run results (diagnostics + resolutions)
- `KnowledgeBaseDocs` – metadata for ingested documents (doc_id, filename, chunks_indexed, user_id, email)
- `ChatHistory` – chat messages, responses, raw tool call traces, async job IDs
- `PrometheusConfigs` – per-user Prometheus datasource configuration

You must create and migrate these tables yourself; see comments in `main.py` and `worker.py` for reference schema examples.

---

## Environment Configuration

The backend relies heavily on environment variables. At a minimum, you should set:

### Core platform
- `SUPABASE_URL` – Supabase project URL
- `SUPABASE_KEY` – Supabase service or anon key (with permissions matching your usage)
- `openrouter` – OpenRouter API key
- `OPENROUTER_MODEL` – default chat model (e.g. `openai/gpt-5.2` or `anthropic/claude-sonnet-4.5`)
- `Pinecone_Api_Key` – Pinecone API key
- `PINECONE_KB_INDEX_NAME` – Pinecone index name for knowledge base (default: `infraai`)

### Incident & chat workers
- `SQS_QUEUE_NAME` – incident SQS FIFO queue name (default: `infraaiqueue.fifo`)
- `SQS_VISIBILITY_TIMEOUT` – per-message visibility timeout in seconds (default: `900`)
- `CHAT_QUEUE_NAME` – async chat queue name (default: `Chatqueue`)
- `WORKER_COUNT` – number of incident worker threads to spawn in-process
- `CHAT_WORKER_COUNT` – number of chat worker threads to spawn in-process

### AWS & Ansible sandbox
- `access_key` – AWS access key used by worker and Ansible sandbox
- `secrete_access` – AWS secret key (note: variable name intentionally misspelled in code)
- `account_id` – AWS account ID used to construct ECR image URL for the Ansible runner

### LLMs & search
- `OPENROUTER_SITE_URL`, `OPENROUTER_SITE_NAME` – optional OpenRouter telemetry headers
- `Gemini_Api_Key` – Google Generative AI key (used by some legacy paths)
- `tavali_api_key` – Tavily search API key

### Secrets & credential storage (Infisical)
- `clientId`, `clientSecret` – Infisical universal auth client credentials
- Infisical workspace is expected to contain per-user secrets named:
  - `AWS_ACCESS_KEY_{email}`, `AWS_SECRET_KEY_{email}`, `AWS_REGION_{email}`
  - `SSH_KEY_{email}`
  - `SNOW_KEY_{email}`, `SNOW_INSTANCE_{email}`, `SNOW_USER_{email}`, `SNOW_PASSWORD_{email}`

### Auth / JWT
- Clerk public key is embedded as a constant; ensure your frontend issues compatible JWTs (RS256, with `email` claim).

---

## Running Locally

### 1. Install dependencies

```bash
cd infra.ai_backend
python -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 2. Set up environment

Create a `.env` file (or export vars in your shell) with the keys listed in **Environment Configuration**. At minimum you need working values for Supabase, OpenRouter, Pinecone, Redis, Infisical, and AWS.

### 3. Start Redis

Redis is required for async chat job status and for some JWT/SSH flows.

```bash
redis-server
```

### 4. Run the HTTP API

Using the FastAPI CLI (matches the provided `Dockerfile`):

```bash
fastapi dev main.py --host 0.0.0.0 --port 8000
```

Or using Uvicorn directly:

```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

This will also start in-process background threads for the incident worker and async chat worker, based on `WORKER_COUNT` and `CHAT_WORKER_COUNT`.

### 5. (Optional) Run the incident worker as a separate process

Instead of using in-process threads, you can run a dedicated worker process:

```bash
python worker.py
```

In this mode you typically set `WORKER_COUNT=0` (or remove the background worker startup) in the API container to avoid duplicate processing.

---

## Docker

### API container

The provided `Dockerfile` builds the FastAPI API image:

```bash
docker build -t infraai-backend .

docker run \
  --env-file .env \
  -p 8000:8000 \
  infraai-backend
```

This uses `fastapi dev main.py` as the container entrypoint.

### Ansible runner image

The `Dockerfiles/Dockerfile` builds the sandboxed Ansible runner image used by `ansible_sandbox.py`. You must build and push this image to ECR yourself and ensure the repository and tag match the `ECR_IMAGE` value constructed in `ansible_sandbox.py`.

---

## Security Considerations

- SSH private keys are fetched from Infisical and stored only temporarily on disk (`key.pem`) with restrictive permissions (`0600`), then deleted.
- Incident logs and AI outputs are truncated before logging to avoid excessive PII or secret exposure.
- ServiceNow, AWS, and SSH credentials are never echoed in logs.
- SQS visibility timeouts are extended to cover the full processing time of long-running incidents.

---

## License

MIT License
