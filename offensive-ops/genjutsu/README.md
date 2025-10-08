# Genjutsu Engine

Pass LLVM pour génération polymorphe de shellcodes avec obfuscation avancée.

## Fonctionnalités

- **Polymorphisme**: Mutation du code à chaque build
- **Virtualisation**: Obfuscation par virtualisation d'instructions
- **Bogus Control Flow**: Ajout de branches fictives
- **Build rapide**: < 3 minutes

## Architecture

```
genjutsu/
├── llvm-pass/         # Pass LLVM C++
├── obfuscator/        # Obfuscator-LLVM integration
├── builder/           # Build orchestration
└── tests/            # Test suite
```

## Usage

```bash
# Build shellcode
genjutsu build --input payload.c --output payload.o --obfuscation-level high

# Options
--obfuscation-level: low, medium, high, extreme
--virtualization: enable instruction virtualization
--bogus-cf: add bogus control flow
--anti-debug: add anti-debugging checks
```

## Performance

- Compilation standard: ~30-60s
- Avec obfuscation high: ~120-150s
- Avec obfuscation extreme: ~150-180s
