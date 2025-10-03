# Offensive Operations Suite

**Regroupant Genjutsu Engine + Ghost Compiler et Hiraishin Framework**

## Vue d'ensemble

Suite d'outils pour opérations offensives avancées avec génération polymorphe de payloads et provisioning ultra-rapide d'infrastructures.

## Composants

### 1. Genjutsu Engine
- Pass LLVM pour génération polymorphe de shellcodes
- Obfuscation avancée (virtualisation, bogus CF)
- Build < 3 minutes

### 2. Ghost Compiler
- Loader Rust `no_std` pour injection reflective in-memory
- Aucune trace sur disque
- Stealth injection avancée

### 3. Hiraishin Framework
- Provisioning/destruction d'infrastructure < 180s
- Rollback instantané < 60s
- IaC avec Terraform + Terragrunt
- Snapshots OCI automatiques

## Performance Targets

| Opération | Target |
|-----------|--------|
| Genjutsu Build | < 3 min |
| Deploy | < 180 s |
| Destroy | < 180 s |
| Rollback | < 60 s |

## Stack Technologique

- **Compilateur**: LLVM/Clang (pass plugin C++)
- **Obfuscation**: Obfuscator-LLVM
- **Langages**: Rust (no_std), Go (CLI), Python (orchestration)
- **IaC**: Terraform, Terragrunt, Nix/Flakes, Packer
- **CI/CD**: GitHub Actions, SBOM CycloneDX, Rekor
- **Monitoring**: Prometheus, Grafana

## Sécurité & Conformité

- TLS 1.3 pour toutes les communications
- SBOM CycloneDX signées et stockées via Rekor
- Audit logs chiffrés
- Conformité ISO 27007

## Structure

```
offensive-ops/
├── genjutsu/          # Engine LLVM pour payloads polymorphes
├── ghost/             # Compiler Rust no_std
├── hiraishin/         # Framework IaC
├── orchestrator/      # Python orchestrateur
├── sbom/             # Génération SBOM et Rekor
└── docs/             # Documentation
```
