# Infra AI Backend

FastAPI service for incident intake, automated remediation workflows, CMDB operations, chat/tool orchestration, and external integrations.

## What this project provides

- Incident ingestion endpoints (`/incidentAdd`, `/incidents/add`)
- SQS-backed worker processing for incident analysis/remediation
- Real-time incident execution streams via SSE (`/incident/stream`, `/api/v1/incidents/stream`)
- CMDB and service inventory APIs
- Knowledge base ingestion/search APIs
- Chat APIs with tool integrations (ServiceNow, GitHub, Jira, Confluence, PagerDuty, Prometheus, Datadog)
- Admin/workflow APIs (approvals, alert types, escalation rules, jobs)

## Tech stack

- Python 3.11
- FastAPI
- Supabase
- AWS (SQS, optional ECS/S3 for automation sandbox)
- OpenRouter / Gemini connectors
- Pinecone
- Redis
- Infisical
- Slack SDK + other integration clients

## Repository layout

- `main.py`: API entrypoint and route definitions
- `worker.py`: incident worker loop and queue processing
- `app/services/incident_service.py`: core remediation logic
- `app/core/*`: config, auth, middleware, DB client, SSE helpers
- `integrations/*`: integration adapters (GitHub, Jira, Confluence, PagerDuty, Prometheus, etc.)
- `migrations/*`: SQL migrations

## Prerequisites

- Python 3.11+
- Access to Supabase project and tables used by this service
- AWS credentials with access to configured SQS queues
- Clerk setup for JWT issuance/verification
- Optional but commonly required: OpenRouter, Pinecone, Infisical, Redis

## Local setup

```bash
cd infra.ai_backend\ copy
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

## Environment variables

Start from `.env.example` and add real secrets.

Important: the current code still reads some legacy env names from `app/core/config.py`. To avoid startup surprises, set both normalized and legacy names for these keys:

- OpenRouter: `OPENROUTER_API_KEY` and `openrouter`
- Pinecone: `PINECONE_API_KEY` and `Pinecone_Api_Key`
- AWS: `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` and `access_key`/`secrete_access`
- Infisical: `INFISICAL_CLIENT_ID`/`INFISICAL_CLIENT_SECRET` and `clientId`/`clientSecret`

Core variables typically needed:

- `SUPABASE_URL`
- `SUPABASE_KEY`
- `SQS_QUEUE_NAME`
- `WORKER_COUNT`
- `CHAT_WORKER_COUNT`
- `OPENROUTER_MODEL`
- `CLERK_SECRET_KEY`

## Run locally

```bash
fastapi dev main.py --host 0.0.0.0 --port 8000
```

Alternative:

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

OpenAPI docs:

- `http://localhost:8000/docs`

## Worker behavior

- Incidents are inserted, then enqueued to SQS from `/incidentAdd` or `/incidents/add`
- Worker loop consumes queue messages and updates incidents/jobs/results
- Worker and chat worker thread counts are controlled by:
  - `WORKER_COUNT`
  - `CHAT_WORKER_COUNT`

## Key API groups

- Incidents:
  - `POST /incidentAdd`
  - `POST /incidents/add`
  - `GET /allIncidents`
  - `GET /getIncidentsDetails/{inc_number}`
  - `GET /getResults/{inc_number}`
- Streaming:
  - `POST /incident/stream`
  - `GET /api/v1/incidents/stream/{inc_number}`
- Chat:
  - `POST /chat`
  - `POST /chat/stream`
  - `POST /chat/async`
  - `GET /chat/async/{job_id}`
- CMDB/Services:
  - `GET/POST /cmdb`
  - `GET/PUT/DELETE /cmdb/{tag_id}`
  - `GET/POST /services`
- Admin/Workflow:
  - `GET/POST/PUT/DELETE /alert-types`
  - `GET/POST/PUT/DELETE /escalation-rules`
  - `POST /pending-actions/{action_id}/approve|reject`

## Migrations

SQL migrations are in `migrations/`. Apply them in your DB deployment pipeline before rolling out new backend code.

## Docker

```bash
docker build -t infra-ai-backend .
docker run --env-file .env -p 8000:8000 infra-ai-backend
```

## Logs and troubleshooting

- Main log files commonly used during local runs:
  - `infra_backend.log`
  - `infra_worker.log`
- Queue health endpoint:
  - `GET /worker/queue-health`
- If incidents stay queued:
  - Verify `SQS_QUEUE_NAME`
  - Verify AWS credentials and queue permissions
  - Verify worker threads are running
