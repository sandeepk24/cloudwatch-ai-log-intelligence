# CloudWatch AI Log Intelligence

Open-source platform that turns AWS CloudWatch logs into actionable incident intelligence.

This repository is the **foundation**: a runnable FastAPI + React app, mock AWS adapters, Terraform for ECS Fargate, and CI. Log Insights queries, metric correlation, and Bedrock reasoning are not implemented yet.

**Repo:** https://github.com/sandeepk24/cloudwatch-ai-log-intelligence

---

## What works today

- FastAPI backend with `/health`, structured JSON logging, and a versioned `/api/v1` envelope
- React 19 + Vite + TypeScript UI (dashboard, investigations placeholder, settings)
- Modular AWS adapters (CloudWatch Logs, CloudWatch Metrics) with a local mock mode
- AI provider interfaces for Amazon Bedrock and Strands Agents (stubs)
- Docker Compose for local backend + frontend
- Terraform skeleton for ECS Fargate, ALB, and read-only investigation IAM
- GitHub Actions for backend tests, frontend tests, and Terraform validate

## What is not implemented

| Capability | Status |
|------------|--------|
| CloudWatch Logs Insights queries | Adapter + mock only |
| CloudWatch Metrics correlation | Adapter + mock only |
| Incident timeline / RCA | Not started |
| Bedrock `InvokeModel` | Interface only |
| Strands Agents runtime | Interface only |
| Live AWS investigation | Disabled unless `AWS_USE_MOCK=false` (still no query engine) |

---

## Local development

### Prerequisites

- Node.js 20+
- Python 3.12+
- Docker (optional, for Compose)

AWS credentials are **not** required for local development. Mock adapters are on by default.

### Backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
cp ../.env.example ../.env
uvicorn app.main:app --reload --port 8000
```

- Health: http://localhost:8000/health
- API docs: http://localhost:8000/docs
- Detailed health: http://localhost:8000/api/v1/health

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:5173. Vite proxies `/api` and `/health` to the backend.

### Docker Compose

```bash
cp .env.example .env
docker compose up --build
```

- UI: http://localhost:8080
- API health: http://localhost:8000/health

---

## Configuration

Copy `.env.example` to `.env`. Important variables:

| Variable | Purpose |
|----------|---------|
| `AWS_USE_MOCK` | `true` (default) uses canned CloudWatch responses |
| `AWS_REGION` | Optional. Empty means the boto3 default chain |
| `AI_PROVIDER` | `bedrock` or `strands` |
| `BEDROCK_MODEL_ID` | Model id when Bedrock is implemented |
| `CORS_ORIGINS` | Allowed frontend origins |
| `LOG_FORMAT` | `json` (default) or `text` |
| `VITE_API_BASE_URL` | Leave empty in Vite; set if the UI talks to the API directly |

**Never put AWS access keys, secret keys, or account IDs in `.env` or the frontend.** The backend uses the standard boto3 credential chain (environment, shared config, or IAM role) when mock mode is off.

---

## Project layout

```
cloudwatch-ai-log-intelligence/
├── frontend/                      React 19 + Vite SPA
├── backend/                       FastAPI app
├── tests/                         Pytest (health, adapters, envelope)
├── docs/                          Architecture
├── infrastructure/terraform/      ECS Fargate, ALB, IAM
├── .github/workflows/             CI
├── docker-compose.yml
├── .env.example
└── README.md
```

---

## Development checks

```bash
# Backend
cd backend && pytest ../tests
cd backend && ruff check . && ruff format --check .

# Frontend
cd frontend && npm run type-check
cd frontend && npm run lint
cd frontend && npm test
cd frontend && npm run build
```

---

## Roadmap

1. **Foundation (this milestone)** — runnable API and UI, mock AWS, CI, Terraform skeleton
2. **Ingestion** — CloudWatch Logs Insights queries with read-only IAM
3. **Analytics** — error clustering, burst detection, noisy-neighbor filters
4. **Correlation** — join log patterns with CloudWatch Metrics and alarms
5. **AI reasoning** — Bedrock / Strands incident briefs with cited log evidence
6. **Operations** — ECS deploy, dashboards, and investigation runbooks

See [docs/architecture.md](docs/architecture.md) for layering, security, and API conventions.

## License

MIT
