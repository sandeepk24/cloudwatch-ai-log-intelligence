# Architecture

CloudWatch AI Log Intelligence turns AWS CloudWatch logs into incident intelligence. This document describes the **foundation**: process boundaries, security rules, and the work that is explicitly not done yet.

## System context

```text
Browser  →  React SPA (Vite)
                │  /api  (no AWS credentials)
                ▼
           FastAPI API
                │
    ┌───────────┼───────────────┐
    ▼           ▼               ▼
 Ingestion   Analytics      Correlation
 (Logs)      (patterns)     (Metrics)
                │
                ▼
          AI reasoning
      Bedrock / Strands
```

Local development uses mock AWS adapters (`AWS_USE_MOCK=true`). Docker Compose runs backend + frontend. Production target is ECS Fargate behind an ALB (`infrastructure/terraform`).

## Layers

| Layer | Location | Responsibility |
|-------|----------|----------------|
| Presentation | `frontend/src/pages`, `components` | Routing, layout, health UI |
| API client | `frontend/src/api` | Typed HTTP only — no `fetch` in pages |
| HTTP API | `backend/app/api/v1` | Versioned REST, envelope responses |
| Services | `backend/app/services` | Use-case orchestration |
| AWS adapters | `backend/app/adapters/aws` | CloudWatch Logs and Metrics |
| AI providers | `backend/app/ai` | Bedrock and Strands behind one protocol |
| Core | `backend/app/core` | Settings, logging, envelope helpers |

Pages must not import FastAPI types, boto3, or Bedrock SDKs. API routers must not import boto3. Adapters must not import API routers.

## Investigation pipeline (future)

These services exist as skeletons so later work has a place to land:

1. **Ingestion** (`services/ingestion.py`) — Logs Insights queries, log group discovery
2. **Analytics** (`services/analytics.py`) — clustering, burst detection, noise reduction
3. **Correlation** (`services/correlation.py`) — join log patterns with CloudWatch Metrics and alarms
4. **Reasoning** (`services/reasoning.py`) — Bedrock / Strands incident briefs with cited evidence

None of these call live AWS or a model in this milestone. Mock adapters return canned log groups and metric series so local tests do not need an account.

## AWS access

- Credentials come from the **standard boto3 chain** (environment, shared config, task role).
- The frontend never receives keys, session tokens, or account IDs.
- `/api/v1/settings` reports mode and region only.
- Terraform attaches a **read-only** investigation policy (`logs:StartQuery`, `logs:GetQueryResults`, `cloudwatch:GetMetricData`, …). Bedrock invoke is a separate optional policy, off by default.
- Region is configuration, not code. Empty `AWS_REGION` means boto3 default chain.

## API conventions

Load balancers use a bare probe:

```http
GET /health
{"status":"ok","version":"0.1.0"}
```

Application routes under `/api/v1/` use a standard envelope:

```json
{
  "success": true,
  "data": {},
  "error": null,
  "meta": {
    "request_id": "uuid",
    "timestamp": "2026-10-30T00:00:00+00:00"
  }
}
```

Unhandled exceptions return `success: false` with `error.code = internal_error` and a generic message. Details stay in structured logs.

## Observability

Backend logs are JSON on stdout (`timestamp`, `level`, `logger`, `message`, optional `request_id`). Every HTTP response includes `X-Request-ID`.

## Runtime

- Frontend: React 19, Vite, TypeScript, Tailwind CSS, TanStack Query, React Router, Vitest
- Backend: Python 3.12+, FastAPI, Pydantic v2, Uvicorn, boto3
- Compose: `backend` (8000), `frontend` (8080, nginx → backend `/api` and `/health`)
- Cloud: ECS Fargate, ALB `/health`, read-only IAM — see `infrastructure/terraform`

## Non-goals of this milestone

- Executing Logs Insights queries against a real account
- Invoking Amazon Bedrock or running Strands agents
- Multi-tenant tenancy, SSO, or audit export
- Writing to customer log groups or changing AWS resources
