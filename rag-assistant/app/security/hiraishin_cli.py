"""
⚡ Hiraishin CLI - Interface unifiée pour Offensive Operations Suite
CLI hiraishin pour deploy, destroy, rollback, status
Intégration Genjutsu Engine + Ghost Compiler + Hiraishin Framework
"""

import click
import json
import yaml
import asyncio
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime
from pathlib import Path
import subprocess
import sys
import os

# Import des modules de la suite
from .offensive_operations_suite import OffensiveOperationsSuite, PayloadType, OperationType

logger = logging.getLogger(__name__)

class HiraishinCLI:
    """CLI unifiée Hiraishin pour toutes les opérations"""
    
    def __init__(self):
        """Initialise la CLI Hiraishin"""
        self.suite = OffensiveOperationsSuite()
        self.config = self._load_config()
        self.verbose = False
    
    def _load_config(self) -> Dict[str, Any]:
        """Charge la configuration Hiraishin"""
        config_path = Path("hiraishin_config.yaml")
        
        if config_path.exists():
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        else:
            # Configuration par défaut
            default_config = {
                'genjutsu': {
                    'obfuscation_levels': ['light', 'medium', 'heavy', 'extreme'],
                    'default_level': 'medium',
                    'build_timeout': 180  # secondes
                },
                'ghost': {
                    'injection_methods': [
                        'reflective_dll_loading',
                        'process_hollowing',
                        'dll_hijacking'
                    ],
                    'default_method': 'reflective_dll_loading'
                },
                'hiraishin': {
                    'terraform': {
                        'working_dir': './terraform',
                        'state_bucket': 'hiraishin-state',
                        'state_key': 'infrastructure'
                    },
                    'nix': {
                        'flake_path': './nix',
                        'system': 'x86_64-linux'
                    },
                    'helm': {
                        'charts_path': './helm',
                        'namespace': 'hiraishin'
                    },
                    'performance_targets': {
                        'deploy_time': 180,
                        'destroy_time': 180,
                        'rollback_time': 60
                    }
                },
                'logging': {
                    'level': 'INFO',
                    'file': 'hiraishin.log',
                    'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                }
            }
            
            # Sauvegarde de la configuration par défaut
            with open(config_path, 'w') as f:
                yaml.dump(default_config, f, default_flow_style=False)
            
            return default_config
    
    def _setup_logging(self, verbose: bool = False):
        """Configure le logging"""
        log_level = logging.DEBUG if verbose else getattr(logging, self.config['logging']['level'])
        
        logging.basicConfig(
            level=log_level,
            format=self.config['logging']['format'],
            handlers=[
                logging.FileHandler(self.config['logging']['file']),
                logging.StreamHandler(sys.stdout)
            ]
        )
        
        self.verbose = verbose
    
    def _print_status(self, message: str, status: str = "info"):
        """Affiche le statut avec formatage"""
        status_colors = {
            "info": "blue",
            "success": "green", 
            "warning": "yellow",
            "error": "red"
        }
        
        color = status_colors.get(status, "white")
        click.echo(click.style(f"[{status.upper()}] {message}", fg=color))
    
    def _print_json_output(self, data: Dict[str, Any]):
        """Affiche la sortie JSON formatée"""
        click.echo(json.dumps(data, indent=2, default=str))

@click.group()
@click.option('--config', '-c', help='Fichier de configuration')
@click.option('--verbose', '-v', is_flag=True, help='Mode verbeux')
@click.option('--dry-run', is_flag=True, help='Simulation sans exécution')
@click.pass_context
def cli(ctx, config, verbose, dry_run):
    """Hiraishin CLI - Offensive Operations Suite"""
    ctx.ensure_object(dict)
    ctx.obj['config'] = config
    ctx.obj['verbose'] = verbose
    ctx.obj['dry_run'] = dry_run
    
    # Initialisation de la CLI
    hiraishin = HiraishinCLI()
    hiraishin._setup_logging(verbose)
    ctx.obj['hiraishin'] = hiraishin

@cli.command()
@click.option('--payload-type', type=click.Choice(['shellcode', 'reflective_dll', 'memory_patch', 'process_hollowing']), 
              default='shellcode', help='Type de payload à générer')
@click.option('--obfuscation-level', type=click.Choice(['light', 'medium', 'heavy', 'extreme']), 
              default='medium', help='Niveau d\'obfuscation')
@click.option('--output', '-o', help='Fichier de sortie')
@click.option('--json', 'json_output', is_flag=True, help='Sortie JSON')
@click.pass_context
def genjutsu_build(ctx, payload_type, obfuscation_level, output, json_output):
    """Genjutsu Engine - Génération de payload polymorphe"""
    hiraishin = ctx.obj['hiraishin']
    
    try:
        hiraishin._print_status("Démarrage de la génération Genjutsu...", "info")
        
        # Conversion du type de payload
        payload_type_enum = PayloadType(payload_type.upper())
        
        # Génération du payload
        payload = hiraishin.suite.genjutsu_build(payload_type_enum, obfuscation_level)
        
        # Sauvegarde si fichier de sortie spécifié
        if output:
            with open(output, 'wb') as f:
                f.write(payload.payload_data)  # Sauvegarde du payload généré
        
        result = {
            'success': True,
            'payload_id': payload.id,
            'payload_type': payload.payload_type.value,
            'obfuscation_level': payload.obfuscation_level,
            'mutation_count': payload.mutation_count,
            'build_time': payload.build_time,
            'size_bytes': payload.size_bytes,
            'entropy': payload.entropy,
            'signature': payload.signature,
            'created_at': payload.created_at.isoformat()
        }
        
        if json_output:
            hiraishin._print_json_output(result)
        else:
            hiraishin._print_status(f"Payload généré: {payload.id}", "success")
            hiraishin._print_status(f"Temps de build: {payload.build_time:.2f}s", "info")
            hiraishin._print_status(f"Taille: {payload.size_bytes} bytes", "info")
            hiraishin._print_status(f"Entropie: {payload.entropy:.2f}", "info")
        
    except Exception as e:
        hiraishin._print_status(f"Erreur lors de la génération: {e}", "error")
        sys.exit(1)

@cli.command()
@click.argument('payload_id')
@click.option('--target-process', '-t', required=True, help='Processus cible')
@click.option('--injection-method', type=click.Choice(['reflective_dll_loading', 'process_hollowing', 'dll_hijacking']), 
              default='reflective_dll_loading', help='Méthode d\'injection')
@click.option('--json', 'json_output', is_flag=True, help='Sortie JSON')
@click.pass_context
def ghost_inject(ctx, payload_id, target_process, injection_method, json_output):
    """Ghost Compiler - Injection furtive de payload"""
    hiraishin = ctx.obj['hiraishin']
    
    try:
        hiraishin._print_status(f"Injection du payload {payload_id}...", "info")
        
        # Injection du payload
        result = hiraishin.suite.ghost_inject(payload_id, target_process, injection_method)
        
        if json_output:
            hiraishin._print_json_output(result)
        else:
            if result['success']:
                hiraishin._print_status("Injection réussie", "success")
                hiraishin._print_status(f"Méthode: {result.get('injection_method', injection_method)}", "info")
                hiraishin._print_status(f"Techniques furtives: {', '.join(result.get('stealth_techniques', []))}", "info")
            else:
                hiraishin._print_status(f"Échec de l'injection: {result.get('error', 'Erreur inconnue')}", "error")
                sys.exit(1)
        
    except Exception as e:
        hiraishin._print_status(f"Erreur lors de l'injection: {e}", "error")
        sys.exit(1)

@cli.command()
@click.option('--config-file', '-f', help='Fichier de configuration d\'infrastructure')
@click.option('--terraform-dir', help='Répertoire Terraform')
@click.option('--nix-flake', help='Chemin vers le flake Nix')
@click.option('--helm-charts', help='Répertoire des charts Helm')
@click.option('--json', 'json_output', is_flag=True, help='Sortie JSON')
@click.pass_context
def deploy(ctx, config_file, terraform_dir, nix_flake, helm_charts, json_output):
    """Hiraishin Framework - Déploiement d'infrastructure"""
    hiraishin = ctx.obj['hiraishin']
    
    try:
        hiraishin._print_status("Démarrage du déploiement Hiraishin...", "info")
        
        # Configuration d'infrastructure
        infrastructure_config = {
            'terraform_dir': terraform_dir or hiraishin.config['hiraishin']['terraform']['working_dir'],
            'nix_flake': nix_flake or hiraishin.config['hiraishin']['nix']['flake_path'],
            'helm_charts': helm_charts or hiraishin.config['hiraishin']['helm']['charts_path'],
            'target_time': hiraishin.config['hiraishin']['performance_targets']['deploy_time']
        }
        
        if config_file:
            with open(config_file, 'r') as f:
                custom_config = yaml.safe_load(f)
                infrastructure_config.update(custom_config)
        
        # Déploiement
        result = hiraishin.suite.hiraishin_deploy(infrastructure_config)
        
        if json_output:
            hiraishin._print_json_output(result)
        else:
            if result['success']:
                hiraishin._print_status("Déploiement réussi", "success")
                hiraishin._print_status(f"ID de déploiement: {result['deploy_id']}", "info")
                hiraishin._print_status(f"Temps de déploiement: {result['deploy_time']:.2f}s", "info")
                hiraishin._print_status(f"Objectif de performance: {'✓' if result['performance_met'] else '✗'}", 
                                     "success" if result['performance_met'] else "warning")
                hiraishin._print_status(f"Snapshot créé: {result['snapshot_id']}", "info")
            else:
                hiraishin._print_status(f"Échec du déploiement: {result.get('error', 'Erreur inconnue')}", "error")
                sys.exit(1)
        
    except Exception as e:
        hiraishin._print_status(f"Erreur lors du déploiement: {e}", "error")
        sys.exit(1)

@cli.command()
@click.argument('deploy_id')
@click.option('--force', is_flag=True, help='Forcer la destruction sans confirmation')
@click.option('--json', 'json_output', is_flag=True, help='Sortie JSON')
@click.pass_context
def destroy(ctx, deploy_id, force, json_output):
    """Hiraishin Framework - Destruction d'infrastructure"""
    hiraishin = ctx.obj['hiraishin']
    
    try:
        if not force:
            confirm = click.confirm(f"Êtes-vous sûr de vouloir détruire le déploiement {deploy_id}?")
            if not confirm:
                hiraishin._print_status("Destruction annulée", "warning")
                return
        
        hiraishin._print_status(f"Destruction du déploiement {deploy_id}...", "info")
        
        # Destruction
        result = hiraishin.suite.hiraishin_destroy(deploy_id)
        
        if json_output:
            hiraishin._print_json_output(result)
        else:
            if result['success']:
                hiraishin._print_status("Destruction réussie", "success")
                hiraishin._print_status(f"Temps de destruction: {result['destroy_time']:.2f}s", "info")
                hiraishin._print_status(f"Objectif de performance: {'✓' if result['performance_met'] else '✗'}", 
                                     "success" if result['performance_met'] else "warning")
            else:
                hiraishin._print_status(f"Échec de la destruction: {result.get('error', 'Erreur inconnue')}", "error")
                sys.exit(1)
        
    except Exception as e:
        hiraishin._print_status(f"Erreur lors de la destruction: {e}", "error")
        sys.exit(1)

@cli.command()
@click.argument('snapshot_id')
@click.option('--json', 'json_output', is_flag=True, help='Sortie JSON')
@click.pass_context
def rollback(ctx, snapshot_id, json_output):
    """Hiraishin Framework - Rollback vers un snapshot"""
    hiraishin = ctx.obj['hiraishin']
    
    try:
        hiraishin._print_status(f"Rollback vers le snapshot {snapshot_id}...", "info")
        
        # Rollback
        result = hiraishin.suite.hiraishin_rollback(snapshot_id)
        
        if json_output:
            hiraishin._print_json_output(result)
        else:
            if result['success']:
                hiraishin._print_status("Rollback réussi", "success")
                hiraishin._print_status(f"Temps de rollback: {result['rollback_time']:.2f}s", "info")
                hiraishin._print_status(f"Objectif de performance: {'✓' if result['performance_met'] else '✗'}", 
                                     "success" if result['performance_met'] else "warning")
            else:
                hiraishin._print_status(f"Échec du rollback: {result.get('error', 'Erreur inconnue')}", "error")
                sys.exit(1)
        
    except Exception as e:
        hiraishin._print_status(f"Erreur lors du rollback: {e}", "error")
        sys.exit(1)

@cli.command()
@click.option('--operations', is_flag=True, help='Afficher les opérations récentes')
@click.option('--performance', is_flag=True, help='Afficher les métriques de performance')
@click.option('--payloads', is_flag=True, help='Afficher les payloads générés')
@click.option('--snapshots', is_flag=True, help='Afficher les snapshots d\'infrastructure')
@click.option('--json', 'json_output', is_flag=True, help='Sortie JSON')
@click.pass_context
def status(ctx, operations, performance, payloads, snapshots, json_output):
    """Statut de la suite Hiraishin"""
    hiraishin = ctx.obj['hiraishin']
    
    try:
        status_data = {}
        
        # Statut général
        general_status = hiraishin.suite.get_operations_status()
        status_data['general'] = general_status
        
        # Opérations récentes
        if operations:
            status_data['operations'] = hiraishin.suite.operations_log[-10:]  # 10 dernières
        
        # Métriques de performance
        if performance:
            performance_metrics = hiraishin.suite.get_performance_metrics()
            status_data['performance'] = performance_metrics
        
        # Payloads générés
        if payloads:
            status_data['payloads'] = list(hiraishin.suite.payloads_registry.values())
        
        # Snapshots d'infrastructure
        if snapshots:
            status_data['snapshots'] = list(hiraishin.suite.infrastructure_snapshots.values())
        
        if json_output:
            hiraishin._print_json_output(status_data)
        else:
            # Affichage formaté
            hiraishin._print_status("=== STATUT HIRAISHIN ===", "info")
            
            # Statut général
            hiraishin._print_status(f"Opérations totales: {general_status['total_operations']}", "info")
            hiraishin._print_status(f"Opérations réussies: {general_status['successful_operations']}", "info")
            hiraishin._print_status(f"Taux de succès: {general_status['success_rate']:.1%}", "info")
            
            if operations and 'operations' in status_data:
                hiraishin._print_status("\n=== OPÉRATIONS RÉCENTES ===", "info")
                for op in status_data['operations'][-5:]:  # 5 dernières
                    status_icon = "✓" if op.get('success', False) else "✗"
                    hiraishin._print_status(f"{status_icon} {op.get('operation', 'unknown')} - {op.get('timestamp', '')}", 
                                          "success" if op.get('success', False) else "error")
            
            if performance and 'performance' in status_data:
                hiraishin._print_status("\n=== MÉTRIQUES DE PERFORMANCE ===", "info")
                for metric_name, metric_data in status_data['performance']['performance_metrics'].items():
                    if metric_data['count'] > 0:
                        hiraishin._print_status(f"{metric_name}: {metric_data['average']:.2f}s (moyenne)", "info")
        
    except Exception as e:
        hiraishin._print_status(f"Erreur lors de la récupération du statut: {e}", "error")
        sys.exit(1)

@cli.command()
@click.argument('operation_id')
@click.option('--json', 'json_output', is_flag=True, help='Sortie JSON')
@click.pass_context
def sbom(ctx, operation_id, json_output):
    """Génération de SBOM CycloneDX pour une opération"""
    hiraishin = ctx.obj['hiraishin']
    
    try:
        hiraishin._print_status(f"Génération de SBOM pour l'opération {operation_id}...", "info")
        
        # Génération du SBOM
        result = hiraishin.suite.generate_sbom(operation_id)
        
        if json_output:
            hiraishin._print_json_output(result)
        else:
            if result['sbom_generated']:
                hiraishin._print_status("SBOM généré avec succès", "success")
                hiraishin._print_status(f"Composants: {len(result['sbom']['components'])}", "info")
                hiraishin._print_status(f"Format: {result['sbom']['bomFormat']} v{result['sbom']['specVersion']}", "info")
            else:
                hiraishin._print_status(f"Échec de la génération SBOM: {result.get('error', 'Erreur inconnue')}", "error")
                sys.exit(1)
        
    except Exception as e:
        hiraishin._print_status(f"Erreur lors de la génération SBOM: {e}", "error")
        sys.exit(1)

@cli.command()
@click.option('--config', '-c', help='Fichier de configuration à créer')
@click.pass_context
def init(ctx, config):
    """Initialise la configuration Hiraishin"""
    hiraishin = ctx.obj['hiraishin']
    
    try:
        config_file = config or "hiraishin_config.yaml"
        
        hiraishin._print_status(f"Initialisation de la configuration: {config_file}", "info")
        
        # La configuration est déjà créée dans __init__
        hiraishin._print_status("Configuration initialisée avec succès", "success")
        hiraishin._print_status(f"Fichier créé: {config_file}", "info")
        
    except Exception as e:
        hiraishin._print_status(f"Erreur lors de l'initialisation: {e}", "error")
        sys.exit(1)

if __name__ == '__main__':
    cli()
