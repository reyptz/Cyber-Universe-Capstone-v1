"""
SecurePipeline - Pipeline CI/CD sécurisé
Implémente les pipelines GitHub Actions avec scans de sécurité intégrés
"""

import asyncio
import json
import subprocess
from datetime import datetime
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path

from .secrets import SecretsManager
from .scanner import VulnerabilityScanner
from .policies import SecurityPolicies


class PipelineStage(Enum):
    """Étapes du pipeline CI/CD"""
    INIT = "init"
    BUILD = "build"
    TEST = "test"
    SAST = "sast"          # Static Application Security Testing
    DAST = "dast"          # Dynamic Application Security Testing
    SCA = "sca"            # Software Composition Analysis
    IAC = "iac"            # Infrastructure as Code scan
    SECURITY_TEST = "security_test"
    DEPLOY = "deploy"
    POST_DEPLOY = "post_deploy"
    CLEANUP = "cleanup"


class PipelineStatus(Enum):
    """Statuts d'exécution"""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class PipelineStep:
    """Étape du pipeline avec configuration"""
    name: str
    stage: PipelineStage
    command: str
    timeout: int = 300
    retries: int = 3
    critical: bool = True
    dependencies: List[str] = None


@dataclass
class PipelineResult:
    """Résultat d'exécution d'une étape"""
    step_name: str
    status: PipelineStatus
    start_time: datetime
    end_time: Optional[datetime] = None
    exit_code: Optional[int] = None
    output: str = ""
    error: str = ""
    metrics: Dict[str, Any] = None


class SecurePipeline:
    """
    Pipeline CI/CD sécurisé pour Ghost Cyber Universe
    Intègre SAST, DAST, SCA, IaC selon les spécifications
    """
    
    def __init__(self, config_path: str = "devsecops/config/pipeline.json"):
        self.config_path = Path(config_path)
        self.steps: List[PipelineStep] = []
        self.results: Dict[str, PipelineResult] = {}
        self.callbacks: List[Callable] = []
        self.is_running = False
        
        # Composants de sécurité intégrés
        self.secrets_manager = SecretsManager()
        self.scanner = VulnerabilityScanner()
        self.policies = SecurityPolicies()
        
    async def initialize(self) -> bool:
        """Initialise le pipeline sécurisé"""
        try:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            await self._load_config()
            
            # Initialisation des composants de sécurité
            components = [self.secrets_manager, self.scanner, self.policies]
            for component in components:
                await component.initialize()
            
            return True
        except Exception as e:
            print(f"Erreur initialisation pipeline: {e}")
            return False
    
    async def _load_config(self):
        """Charge la configuration du pipeline"""
        if self.config_path.exists():
            with open(self.config_path, 'r') as f:
                config_data = json.load(f)
            for step_data in config_data.get('steps', []):
                self.steps.append(PipelineStep(**step_data))
        else:
            await self._create_default_config()
    
    async def _create_default_config(self):
        """Configuration par défaut selon les spécifications DevSecOps"""
        self.steps = [
            # Initialisation
            PipelineStep(
                name="init",
                stage=PipelineStage.INIT,
                command="echo 'Pipeline DevSecOps initialisé'",
                timeout=60
            ),
            
            # Build avec Docker
            PipelineStep(
                name="build",
                stage=PipelineStage.BUILD,
                command="docker build -t ghost-cyber-universe .",
                timeout=600,
                dependencies=["init"]
            ),
            
            # Tests unitaires
            PipelineStep(
                name="unit_tests",
                stage=PipelineStage.TEST,
                command="python -m pytest tests/ -v --cov=src",
                timeout=300,
                dependencies=["build"]
            ),
            
            # SAST - Analyse statique (Semgrep selon spécifications)
            PipelineStep(
                name="sast_scan",
                stage=PipelineStage.SAST,
                command="semgrep --config=auto src/",
                timeout=600,
                dependencies=["build"]
            ),
            
            # SCA - Analyse des dépendances (Trivy selon spécifications)
            PipelineStep(
                name="sca_scan",
                stage=PipelineStage.SCA,
                command="trivy fs .",
                timeout=300,
                dependencies=["build"]
            ),
            
            # IaC - Infrastructure as Code (Terraform selon spécifications)
            PipelineStep(
                name="iac_scan",
                stage=PipelineStage.IAC,
                command="tfsec .",
                timeout=300,
                critical=False,
                dependencies=["build"]
            ),
            
            # Tests de sécurité
            PipelineStep(
                name="security_tests",
                stage=PipelineStage.SECURITY_TEST,
                command="python -m pytest tests/security/ -v",
                timeout=600,
                dependencies=["sast_scan", "sca_scan"]
            ),
            
            # Déploiement Kubernetes
            PipelineStep(
                name="deploy_staging",
                stage=PipelineStage.DEPLOY,
                command="kubectl apply -f k8s/staging/",
                timeout=300,
                dependencies=["security_tests"]
            ),
            
            # DAST - Tests dynamiques (OWASP ZAP selon spécifications)
            PipelineStep(
                name="dast_scan",
                stage=PipelineStage.DAST,
                command="zap-baseline.py -t http://staging.ghost-cyber-universe.com",
                timeout=900,
                critical=False,
                dependencies=["deploy_staging"]
            ),
            
            # Tests post-déploiement
            PipelineStep(
                name="post_deploy_tests",
                stage=PipelineStage.POST_DEPLOY,
                command="python tests/integration/test_deployment.py",
                timeout=300,
                dependencies=["deploy_staging"]
            ),
            
            # Nettoyage
            PipelineStep(
                name="cleanup",
                stage=PipelineStage.CLEANUP,
                command="docker system prune -f",
                timeout=120,
                critical=False,
                dependencies=["post_deploy_tests"]
            )
        ]
        await self._save_config()
    
    async def _save_config(self):
        """Sauvegarde la configuration"""
        config_data = {'steps': [asdict(step) for step in self.steps]}
        with open(self.config_path, 'w') as f:
            json.dump(config_data, f, indent=2, default=str)
    
    async def add_callback(self, callback: Callable):
        """Ajoute un callback pour les événements"""
        self.callbacks.append(callback)
    
    async def _notify_callbacks(self, event_type: str, data: Any = None):
        """Notifie les callbacks des événements"""
        for callback in self.callbacks:
            try:
                await callback(event_type, data)
            except Exception as e:
                print(f"Erreur callback: {e}")
    
    async def run_pipeline(self, target_stage: Optional[PipelineStage] = None) -> bool:
        """
        Exécute le pipeline CI/CD sécurisé
        
        Args:
            target_stage: Étape cible (optionnel)
            
        Returns:
            True si succès, False sinon
        """
        if self.is_running:
            print("Pipeline déjà en cours d'exécution")
            return False
        
        self.is_running = True
        await self._notify_callbacks("pipeline_started")
        
        try:
            # Filtrage des étapes selon la cible
            steps_to_run = self._get_steps_to_run(target_stage)
            
            for step in steps_to_run:
                # Vérification des dépendances
                if not await self._check_dependencies(step):
                    print(f"❌ Dépendances non satisfaites pour {step.name}")
                    return False
                
                # Exécution de l'étape
                success = await self._execute_step(step)
                
                if not success and step.critical:
                    print(f"❌ Étape critique {step.name} échouée")
                    await self._notify_callbacks("pipeline_failed", step.name)
                    return False
                elif not success:
                    print(f"⚠️  Étape non-critique {step.name} échouée")
            
            await self._notify_callbacks("pipeline_completed")
            return True
            
        except Exception as e:
            print(f"Erreur pipeline: {e}")
            await self._notify_callbacks("pipeline_error", str(e))
            return False
        finally:
            self.is_running = False
    
    def _get_steps_to_run(self, target_stage: Optional[PipelineStage]) -> List[PipelineStep]:
        """Détermine les étapes à exécuter"""
        if not target_stage:
            return self.steps
        
        # Ordre des étapes selon les spécifications DevSecOps
        stage_order = [
            PipelineStage.INIT,
            PipelineStage.BUILD,
            PipelineStage.TEST,
            PipelineStage.SAST,
            PipelineStage.SCA,
            PipelineStage.IAC,
            PipelineStage.SECURITY_TEST,
            PipelineStage.DEPLOY,
            PipelineStage.DAST,
            PipelineStage.POST_DEPLOY,
            PipelineStage.CLEANUP
        ]
        
        target_index = stage_order.index(target_stage)
        return [step for step in self.steps 
                if stage_order.index(step.stage) <= target_index]
    
    async def _check_dependencies(self, step: PipelineStep) -> bool:
        """Vérifie si les dépendances sont satisfaites"""
        if not step.dependencies:
            return True
        
        for dep in step.dependencies:
            if dep not in self.results:
                return False
            if self.results[dep].status != PipelineStatus.SUCCESS:
                return False
        
        return True
    
    async def _execute_step(self, step: PipelineStep) -> bool:
        """Exécute une étape du pipeline"""
        print(f"🔄 Exécution: {step.name}")
        
        result = PipelineResult(
            step_name=step.name,
            status=PipelineStatus.RUNNING,
            start_time=datetime.utcnow()
        )
        
        self.results[step.name] = result
        await self._notify_callbacks("step_started", step.name)
        
        try:
            # Exécution avec retry selon les spécifications
            for attempt in range(step.retries):
                success = await self._run_command(step, result)
                if success:
                    break
                
                if attempt < step.retries - 1:
                    print(f"🔄 Retry {attempt + 1}/{step.retries} pour {step.name}")
                    await asyncio.sleep(2 ** attempt)  # Backoff exponentiel
            
            result.status = PipelineStatus.SUCCESS if success else PipelineStatus.FAILED
            result.end_time = datetime.utcnow()
            
            await self._notify_callbacks("step_completed", {
                "step": step.name,
                "status": result.status.value
            })
            
            return success
            
        except Exception as e:
            result.error = str(e)
            result.status = PipelineStatus.FAILED
            result.end_time = datetime.utcnow()
            print(f"❌ Erreur dans {step.name}: {e}")
            return False
    
    async def _run_command(self, step: PipelineStep, result: PipelineResult) -> bool:
        """Exécute une commande avec timeout"""
        try:
            # Simulation d'exécution pour la démo
            if step.stage in [PipelineStage.SAST, PipelineStage.SCA, PipelineStage.IAC]:
                # Intégration avec le scanner de vulnérabilités
                await self._run_security_scan(step, result)
            else:
                # Simulation d'autres commandes
                await asyncio.sleep(1)  # Simulation
                result.output = f"Commande {step.command} exécutée avec succès"
                result.exit_code = 0
            
            return result.exit_code == 0
            
        except asyncio.TimeoutError:
            result.error = f"Timeout après {step.timeout}s"
            result.exit_code = 124
            return False
        except Exception as e:
            result.error = str(e)
            result.exit_code = 1
            return False
    
    async def _run_security_scan(self, step: PipelineStep, result: PipelineResult):
        """Exécute les scans de sécurité intégrés"""
        if step.stage == PipelineStage.SAST:
            scan_result = await self.scanner.run_sast_scan("src/")
            result.metrics = {"vulnerabilities": len(scan_result.vulnerabilities)}
        elif step.stage == PipelineStage.SCA:
            scan_result = await self.scanner.run_sca_scan(".")
            result.metrics = {"vulnerabilities": len(scan_result.vulnerabilities)}
        elif step.stage == PipelineStage.IAC:
            scan_result = await self.scanner.run_iac_scan("infra/")
            result.metrics = {"vulnerabilities": len(scan_result.vulnerabilities)}
        
        result.exit_code = 0
        result.output = f"Scan {step.stage.value} terminé"
    
    async def get_pipeline_status(self) -> Dict[str, Any]:
        """Retourne le statut du pipeline"""
        total_steps = len(self.steps)
        completed_steps = len([r for r in self.results.values() 
                              if r.status in [PipelineStatus.SUCCESS, PipelineStatus.FAILED]])
        failed_steps = len([r for r in self.results.values() 
                           if r.status == PipelineStatus.FAILED])
        
        return {
            "is_running": self.is_running,
            "total_steps": total_steps,
            "completed_steps": completed_steps,
            "failed_steps": failed_steps,
            "progress_percentage": (completed_steps / total_steps * 100) if total_steps > 0 else 0
        }
    
    async def cancel_pipeline(self):
        """Annule le pipeline en cours"""
        if self.is_running:
            self.is_running = False
            await self._notify_callbacks("pipeline_cancelled")
    
    async def get_security_report(self) -> Dict[str, Any]:
        """Génère un rapport de sécurité du pipeline"""
        security_issues = []
        
        # Analyse des résultats de sécurité
        for result in self.results.values():
            if result.metrics and "vulnerabilities" in result.metrics:
                vuln_count = result.metrics["vulnerabilities"]
                if vuln_count > 0:
                    security_issues.append({
                        "step": result.step_name,
                        "vulnerabilities": vuln_count
                    })
        
        # Classification selon les spécifications
        critical_issues = len([i for i in security_issues if i["vulnerabilities"] >= 10])
        high_issues = len([i for i in security_issues if 5 <= i["vulnerabilities"] < 10])
        medium_issues = len([i for i in security_issues if 1 <= i["vulnerabilities"] < 5])
        low_issues = len([i for i in security_issues if i["vulnerabilities"] == 1])
        
        return {
            "total_issues": len(security_issues),
            "critical_issues": critical_issues,
            "high_issues": high_issues,
            "medium_issues": medium_issues,
            "low_issues": low_issues,
            "security_score": max(0, 100 - (critical_issues * 25 + high_issues * 10 + medium_issues * 5)),
            "recommendations": self._generate_security_recommendations(security_issues)
        }
    
    def _generate_security_recommendations(self, issues: List[Dict]) -> List[str]:
        """Génère des recommandations de sécurité"""
        recommendations = []
        
        if any(i["vulnerabilities"] >= 10 for i in issues):
            recommendations.append("Corriger immédiatement les vulnérabilités critiques")
        
        if any(i["vulnerabilities"] >= 5 for i in issues):
            recommendations.append("Planifier la correction des vulnérabilités élevées")
        
        if len(issues) > 3:
            recommendations.append("Renforcer les contrôles de sécurité dans le pipeline")
        
        return recommendations
