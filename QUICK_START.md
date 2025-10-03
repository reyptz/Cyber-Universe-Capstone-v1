# Ghost Cyber Universe - Quick Start Guide

## 🚀 Démarrage Rapide (5 minutes)

### Prérequis

- **Docker** & **Docker Compose**
- **Git**
- **Python 3.11+**
- **Node.js 18+**
- **Rust 1.75+** (pour Offensive Ops)
- **Go 1.21+** (pour Offensive Ops)

### Installation Automatique

```bash
# 1. Cloner le repository
git clone https://github.com/reyptz/ghost-cyber-universe.git
cd ghost-cyber-universe

# 2. Rendre le script exécutable
chmod +x setup.sh

# 3. Lancer l'installation complète
./setup.sh all

# OU installation sélective :
./setup.sh offensive    # Offensive Ops uniquement
./setup.sh defensive    # Defensive Ops uniquement
./setup.sh monitoring   # Monitoring uniquement
```

### Installation Manuelle

#### Option 1 : Docker Compose (Recommandé)

```bash
# Démarrer tous les services
docker-compose up -d

# Vérifier le statut
docker-compose ps

# Voir les logs
docker-compose logs -f
```

#### Option 2 : Installation Locale

##### Defensive Platform

```bash
# Backend (Shinra)
cd defensive-ops/shinra
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn api.main:app --reload --port 8000

# Frontend
cd ../frontend
npm install
npm run dev
```

##### Offensive Operations

```bash
# Genjutsu Engine
cd offensive-ops/genjutsu
./build.sh

# Ghost Compiler
cd ../ghost
cargo build --release

# Hiraishin CLI
cd ../hiraishin/cli
go build -o hiraishin main.go
```

---

## 📊 Accès aux Services

| Service | URL | Credentials |
|---------|-----|-------------|
| **Grafana** | http://localhost:3000 | admin / admin |
| **Prometheus** | http://localhost:9090 | - |
| **Shinra API** | http://localhost:8000 | - |
| **API Docs** | http://localhost:8000/api/docs | - |
| **Frontend** | http://localhost:5173 | admin / admin |
| **Kibana** | http://localhost:5601 | - |
| **MongoDB** | mongodb://localhost:27017 | admin / changeme |

---

## 🎯 Tests Rapides

### Tester l'API Shinra

```bash
# Health check
curl http://localhost:8000/api/health

# Obtenir un token
curl -X POST http://localhost:8000/api/auth/token \
  -d "username=admin&password=admin"

# Créer une mission OSINT
curl -X POST http://localhost:8000/api/missions \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test Mission",
    "targets": ["https://example.com"],
    "depth": 2,
    "crawler_modules": ["http"]
  }'
```

### Tester Hiraishin CLI

```bash
cd offensive-ops/hiraishin/cli

# Voir l'aide
./hiraishin --help

# Déployer (dry-run)
./hiraishin deploy --config example.yaml --dry-run

# Voir le status
./hiraishin status
```

### Lancer les Tests

```bash
# Tests Backend
cd defensive-ops/shinra
pytest tests/ -v --cov=.

# Tests Detection Engine
cd ../kumoshield/detection
python -m pytest tests/ -v

# Tests Frontend
cd ../../frontend
npm test
```

---

## 📈 Monitoring

### Prometheus Queries

```promql
# OSINT Collection Rate
rate(shinra_pages_collected_total[1m]) * 60

# Detection Latency (p95)
histogram_quantile(0.95, rate(detection_latency_milliseconds_bucket[5m]))

# System Uptime
avg_over_time(up{job="shinra-api"}[24h]) * 100
```

### Grafana Dashboards

1. **Offensive Ops**: http://localhost:3000/d/offensive-ops
2. **Defensive Ops**: http://localhost:3000/d/defensive-ops

---

## 🔧 Configuration

### Variables d'Environnement

Créer un fichier `.env` :

```bash
# MongoDB
MONGODB_URL=mongodb://admin:changeme@localhost:27017

# Redis
REDIS_URL=redis://localhost:6379

# Kafka
KAFKA_BOOTSTRAP_SERVERS=localhost:9092

# API
API_SECRET_KEY=your-secret-key-here
API_ALGORITHM=HS256

# Log Level
LOG_LEVEL=INFO
```

### Hiraishin Configuration

Créer `hiraishin.yaml` :

```yaml
cluster:
  name: my-cluster
  nodes: 3
  region: us-east-1

snapshots:
  enabled: true
  interval: 1h
  retention: 24h

security:
  tls: true
  encryption: aes-256-gcm
```

---

## 🛠️ Commandes Utiles

### Docker

```bash
# Redémarrer un service
docker-compose restart shinra-api

# Voir les logs d'un service
docker-compose logs -f shinra-api

# Exécuter une commande dans un container
docker-compose exec shinra-api bash

# Nettoyer tout
docker-compose down -v
```

### Base de données

```bash
# Accéder à MongoDB
docker-compose exec mongodb mongo -u admin -p changeme

# Accéder à Redis
docker-compose exec redis redis-cli
```

---

## 🐛 Troubleshooting

### Problème : Port déjà utilisé

```bash
# Trouver le processus
lsof -i :8000  # Linux/Mac
netstat -ano | findstr :8000  # Windows

# Modifier le port dans docker-compose.yml
ports:
  - "8001:8000"  # Utiliser 8001 au lieu de 8000
```

### Problème : Build Docker échoue

```bash
# Nettoyer le cache
docker-compose build --no-cache

# Vérifier les logs
docker-compose logs --tail=100 shinra-api
```

### Problème : Services ne démarrent pas

```bash
# Vérifier les resources Docker
docker system df

# Nettoyer les images inutilisées
docker system prune -a

# Augmenter la mémoire Docker
# Settings → Resources → Memory → 8GB
```

---

## 📚 Documentation Complète

- **Guide d'implémentation**: [IMPLEMENTATION_GUIDE.md](IMPLEMENTATION_GUIDE.md)
- **Résumé du projet**: [PROJECT_SUMMARY.md](PROJECT_SUMMARY.md)
- **Conformité CDC**: [CAHIERS_DES_CHARGES_IMPLEMENTATION.md](CAHIERS_DES_CHARGES_IMPLEMENTATION.md)
- **Offensive Ops**: [offensive-ops/README.md](offensive-ops/README.md)
- **Defensive Ops**: [defensive-ops/README.md](defensive-ops/README.md)

---

## 🆘 Support

- **Issues**: https://github.com/reyptz/ghost-cyber-universe/issues
- **Email**: reypotozy@gmail.com
- **Documentation**: Voir les fichiers README dans chaque module

---

## ✅ Checklist de Démarrage

- [ ] Prérequis installés (Docker, Python, Node, Rust, Go)
- [ ] Repository cloné
- [ ] `setup.sh` exécuté avec succès
- [ ] Services Docker démarrés (`docker-compose ps`)
- [ ] Grafana accessible (http://localhost:3000)
- [ ] API Shinra répond (http://localhost:8000/api/health)
- [ ] Frontend accessible (http://localhost:5173)
- [ ] Tests passent (`pytest`, `npm test`)

---

**Prêt à commencer ? Lancez `./setup.sh all` ! 🚀**
