# Defensive Intelligence Platform

**Regroupant Shinra OSINT Agent et KumoShield S-IA (SOC-as-Code)**

## Vue d'ensemble

Plateforme unifiée pour collecte OSINT, détection temps réel et réponse coordonnée avec playbooks automatisés.

## Composants

### 1. Shinra OSINT Agent
- Crawlers modulables (HTTP, API, JS)
- RAG avec Pinecone/Chroma
- Workflow collaboratif Kanban
- Distinction faits vs analyses

### 2. KumoShield S-IA (SOC-as-Code)
- eBPF sensors (Rust aya-rs/redbpf)
- Règles Sigma/YARA
- Modèles ML pour anomalies (Isolation Forest)
- GitOps avec attestations SLSA v1.2

## Performance Targets

| Métrique | Target |
|----------|--------|
| Collecte OSINT | 1000 pages/min |
| Détection | < 200 ms |
| Uptime SLA | 99.5% |
| Test Coverage | > 80% |

## Stack Technologique

### Backend
- **Framework**: FastAPI + Pydantic + Uvicorn/Gunicorn
- **Langages**: Python (LangChain, Celery), Rust (eBPF)
- **BDD**: MongoDB, Redis
- **Messaging**: Kafka, Redis, Celery

### Frontend
- **Framework**: React + TypeScript
- **UI**: TailwindCSS + shadcn/ui
- **Icons**: Lucide

### AI/ML
- **Vector Search**: Pinecone, Chroma
- **LLMs**: Llama 2, Mistral (local via LangChain)
- **ML**: scikit-learn (Isolation Forest)

### CI/CD & GitOps
- **Pipeline**: GitHub Actions
- **GitOps**: ArgoCD
- **Attestations**: Sigstore/Cosign (SLSA v1.2)

### Monitoring
- **Métriques**: Prometheus + Alertmanager
- **Dashboards**: Grafana
- **Logs**: ELK Stack (FluentD)

## Sécurité & Conformité

- HTTPS/TLS partout
- RBAC (JWT/OAuth2)
- RGPD/PII: détection et anonymisation automatiques
- ISO 27001/27007 playbooks
- SBOM et audit logs immuables

## Structure

```
defensive-ops/
├── shinra/            # OSINT Agent
│   ├── crawlers/      # Modules de collecte
│   ├── rag/           # RAG avec vector DB
│   ├── workflow/      # Kanban et collaboration
│   └── api/           # FastAPI backend
├── kumoshield/        # SOC-as-Code
│   ├── sensors/       # eBPF sensors Rust
│   ├── detection/     # Sigma/YARA/ML
│   ├── playbooks/     # Réponse automatisée
│   └── gitops/        # ArgoCD config
├── frontend/          # React + TypeScript
├── infra/            # K8s/Helm charts
└── docs/             # Documentation
```
