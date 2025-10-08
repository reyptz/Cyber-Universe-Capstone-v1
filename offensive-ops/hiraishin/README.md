# Hiraishin Framework

Infrastructure-as-Code framework for ultra-fast provisioning, destruction, and rollback.

## Features

- **Deploy**: Provision complete infrastructure < 180s
- **Destroy**: Tear down everything < 180s
- **Rollback**: Restore previous state < 60s
- **Snapshots**: Automatic OCI snapshots

## Architecture

```
hiraishin/
├── cli/               # Go CLI
├── terraform/         # Terraform modules
├── terragrunt/        # Terragrunt configs
├── nix/              # Nix flakes for dependencies
├── packer/           # Packer templates for AMI/OCI
└── k3s/              # K3s Helm charts
```

## Usage

```bash
# Deploy infrastructure
hiraishin deploy --config production.yaml --verbose

# Destroy infrastructure
hiraishin destroy --config production.yaml --confirm

# Rollback to previous snapshot
hiraishin rollback --snapshot snap-2024-01-01 --fast

# List snapshots
hiraishin snapshots list

# Show status
hiraishin status --detailed
```

## Configuration

```yaml
# production.yaml
cluster:
  name: red-team-ops
  nodes: 5
  region: us-east-1
  
snapshots:
  enabled: true
  interval: 1h
  retention: 24h
  
security:
  tls: true
  encryption: aes-256-gcm
  lock_provider: dynamodb
```

## Performance Targets

| Operation | Target | Current |
|-----------|--------|---------|
| Deploy | < 180s | ~120s |
| Destroy | < 180s | ~90s |
| Rollback | < 60s | ~45s |
