# Infra AI Backend

## Overview
Infra AI Backend is a FastAPI-based automation platform for incident management, infrastructure operations, and CMDB/knowledge-base management. It integrates:

- **Supabase** – primary data store for users, incidents, CMDB, results, knowledge docs, Prometheus configs, and chat history.
- **AWS** – SQS (incident & chat queues), EC2 (targets), ECS Fargate (Ansible sandbox), S3 & CloudWatch Logs.
- **Pinecone** – vector knowledge base for SOPs/runbooks.
- **OpenRouter LLMs** – core reasoning engine (chat, diagnostics, automation, ServiceNow helper).
- **Infisical** – secret management for per-user AWS, SSH, ServiceNow, GitHub, Jira, Confluence, and PagerDuty credentials.
- **Redis** – async chat job state and JWT handoff for SSH.
- **Prometheus** – optional metrics context to guide diagnostics.
- **ServiceNow** – incident integration (create/update/fetch).
- **GitHub, Jira, Confluence, PagerDuty** – extended integrations for development, project management, and on-call workflows.

The backend exposes both synchronous HTTP APIs and long-running background workers for self-healing incident resolution.

---

## High-Level Architecture

### Logical Components

1. **HTTP API service (FastAPI)**
   - Main entrypoint: `main.py`
   - Provides REST endpoints for:
     - Chat and infra automation
     - Incident creation and listing
     - CMDB CRUD
     - Knowledge-base ingestion & search
     - Credential management (AWS, SSH, ServiceNow, GitHub, Jira, Confluence, PagerDuty)
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
     - **GitHub**: Search issues/commits, get details (PR diffs support)
     - **Jira**: Search/get issues
     - **Confluence**: Search/get pages
     - **PagerDuty**: List/get incidents
     - **Prometheus**: Query metrics
   - Chat history persisted in Supabase

---

## Data & Control Flows

### 1. Incident auto-remediation pipeline

1. **Incident creation**
   - Frontend calls `POST /incidentAdd` on `main.py`.
   - Supports creation from manual input or PagerDuty webhooks.
   - Backend inserts a row into the `Incidents` table.
   - The same request enqueues a message into the AWS SQS FIFO queue `infraaiqueue.fifo` with incident meta and minimal AWS stub config.

2. **Incident queue consumption**
   - The incident worker (`worker_loop`) polls `infraaiqueue.fifo`.
   - It fetches credentials (AWS, SSH) from Infisical based on the user associated with the incident.

3. **Context enrichment**
   - CMDB lookup in Supabase via `tag_id` or `instance_id`.
   - Knowledge base context via Pinecone (SOPs, runbooks).
   - Prometheus metrics (if configured) queried from the host.

4. **Diagnostics & Resolution**
   - Worker generates a diagnostic plan via LLM.
   - Executes diagnostics on the host via SSH.
   - Analyzes results to determine root cause.
   - Executes resolution steps via SSH.
   - Updates `Incidents` and `Results` tables in Supabase.

### 2. Chat and tool orchestration

1. **Synchronous chat (`POST /chat`)**
   - Authenticated via JWT.
   - System prompt enforces `ask_knowledge_base` first.
   - Tools available include ServiceNow, CMDB, Infra Automation, and the new integrations (GitHub, Jira, Confluence, PagerDuty).

2. **Async chat (`POST /chat/async`)**
   - Enqueues request into `Chatqueue`.
   - Processed by `chat_worker_loop` which stores results in Redis.
   - Client polls `GET /chat/async/{job_id}` for status.

---

## Features & Integrations

### Core Features
- **Auto-Remediation**: Self-healing for infrastructure incidents via SSH and Ansible.
- **RAG Knowledge Base**: Ingest SOPs (PDF/Text) and Architecture docs into Pinecone for context-aware answers.
- **CMDB**: Manage assets and link them to owners and incidents.
- **Infra Automation**: Natural language to Ansible playbook generation and execution in a sandboxed ECS environment.

### Extended Integrations
New integrations allow the agent to interact with your wider DevOps ecosystem. Credentials for these are securely stored in Infisical per-user.

- **GitHub**:
  - Search issues and commits (`/integrations/github/issues/search`, `/integrations/github/commits/search`).
  - Get detailed issue/PR info including diffs.
- **Jira**:
  - Search issues via JQL (`/integrations/jira/issues/search`).
  - Get issue details.
- **Confluence**:
  - Search pages via CQL (`/integrations/confluence/pages/search`).
  - Retrieve page content.
- **PagerDuty**:
  - List incidents by status (`/integrations/pagerduty/incidents`).
  - Get incident details.
- **Prometheus**:
  - Configure datasources (`/prometheus/config`).
  - Execute instant queries (`/integrations/prometheus/query`).

---

## API Endpoints Summary

### Knowledge Base
- `POST /addKnowledge`: Ingest SOP/Docs.
- `POST /knowledge/architecture`: Ingest global architecture docs.
- `GET /getKnowledge`: Query KB.
- `GET /knowledge/docs`: List user's KB docs.
- `DELETE /knowledge/{doc_id}`: Remove a doc.

### CMDB
- `GET /cmdb`: List all items.
- `POST /cmdb`: Create item.
- `GET /cmdb/{tag_id}`: Get item.
- `PUT /cmdb/{tag_id}`: Update item.
- `DELETE /cmdb/{tag_id}`: Delete item.

### Incidents & Queue
- `POST /incidentAdd`: Create incident (Manual/PagerDuty).
- `POST /queueAdd`, `/queueRemove`: Direct SQS control (low-level).
- `POST /storeResult`: Manually store resolution results.
- `GET /getResults/{inc_number}`: Retrieve results.

### Integrations Config & Actions
Each integration (GitHub, Jira, Confluence, PagerDuty, Prometheus) has:
- `GET .../config`: Retrieve current config (masked).
- `POST .../config`: Update config (stored in Infisical).
- Specific action endpoints (e.g., searches, queries).

---

## Environment Configuration

The backend relies on environment variables. Create a `.env` file:

### Core Platform
- `SUPABASE_URL` – Supabase project URL
- `SUPABASE_KEY` – Supabase service/anon key
- `openrouter` – OpenRouter API key
- `OPENROUTER_MODEL` – Default chat model (e.g., `openai/gpt-5.2`)
- `Pinecone_Api_Key` – Pinecone API key
- `PINECONE_KB_INDEX_NAME` – Default `infraai`

### Worker Configuration
- `SQS_QUEUE_NAME` – Default `infraaiqueue.fifo`
- `CHAT_QUEUE_NAME` – Default `Chatqueue`
- `WORKER_COUNT` – Incident worker threads (default 1)
- `CHAT_WORKER_COUNT` – Chat worker threads (default 1)

### AWS & Sandbox
- `access_key`, `secrete_access`, `region` – AWS credentials for the backend process itself (for SQS/S3/ECS control).
- `account_id` – AWS Account ID for ECR.

### Secrets & Integrations (Infisical)
- `clientId`, `clientSecret` – Infisical universal auth credentials.
- **Per-User Integration Secrets**: The backend uses these credentials to fetch per-user keys from Infisical workspace.
  - Users configure their keys (Github Token, Jira API Token, etc.) via the `/integrations/.../config` endpoints, which the backend saves to Infisical.

### Auth
- `clerk_public_key` – Embedded RSA key for verifying frontend JWTs.

---

## Running Locally

1. **Install Dependencies**:
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

2. **Start Redis**:
   ```bash
   redis-server
   ```

3. **Run API**:
   ```bash
   fastapi dev main.py --host 0.0.0.0 --port 8000
   ```

4. **Run Worker (Optional)**:
   If not using in-process threads:
   ```bash
   python worker.py
   ```

---

## Docker

Build and run the backend:
```bash
docker build -t infraai-backend .
docker run --env-file .env -p 8000:8000 infraai-backend
```

---

## Security
- **Secret Zero**: Only Infisical client secrets are stored in the backend env. All downstream integration keys (AWS, SSH, GitHub, etc.) are fetched dynamically per user.
- **Sandboxing**: Ansible runs in isolated ECS Fargate tasks.
- **PII/Context**: Logs are structured and truncated to avoid leaking sensitive prompt data.
