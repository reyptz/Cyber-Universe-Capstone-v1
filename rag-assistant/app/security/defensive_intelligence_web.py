"""
Defensive Intelligence Platform - Interface Web
Shinra OSINT Agent + KumoShield S-IA (SOC-as-Code)
Interface Web unifiée pour analystes, relecteurs, administrateurs
"""

import json
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from enum import Enum
import asyncio
from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
import uvicorn
from pathlib import Path

# Import des modules de la plateforme
from .cyber_threat_intelligence import CyberThreatIntelligence, OSINTSource, ThreatLevel, DetectionType

logger = logging.getLogger(__name__)

# Modèles Pydantic pour l'API
class OSINTMissionCreate(BaseModel):
    name: str = Field(..., description="Nom de la mission")
    targets: List[str] = Field(..., description="Cibles à surveiller")
    depth: int = Field(3, description="Profondeur de collecte")
    frequency: str = Field("daily", description="Fréquence de collecte")

class OSINTMissionResponse(BaseModel):
    id: str
    name: str
    targets: List[str]
    depth: int
    frequency: str
    status: str
    created_at: datetime
    last_run: Optional[datetime] = None
    findings_count: int = 0

class ThreatDetectionRequest(BaseModel):
    data: Dict[str, Any] = Field(..., description="Données à analyser")
    detection_types: List[str] = Field(default=["ebpf", "sigma", "yara", "ml"], description="Types de détection")

class KanbanCardMove(BaseModel):
    card_id: str = Field(..., description="ID de la carte")
    from_column: str = Field(..., description="Colonne source")
    to_column: str = Field(..., description="Colonne destination")

class NotificationRequest(BaseModel):
    type: str = Field(..., description="Type de notification")
    message: str = Field(..., description="Message de notification")
    recipients: List[str] = Field(..., description="Destinataires")

class DefensiveIntelligenceWeb:
    """Interface Web pour la plateforme Defensive Intelligence"""
    
    def __init__(self):
        """Initialise l'interface web"""
        self.app = FastAPI(
            title="Defensive Intelligence Platform",
            description="Shinra OSINT Agent + KumoShield S-IA (SOC-as-Code)",
            version="1.0.0"
        )
        
        # Configuration CORS
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],  # En production, spécifier les domaines autorisés
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        
        # Sécurité
        self.security = HTTPBearer()
        
        # Connexions WebSocket
        self.active_connections: List[WebSocket] = []
        
        # Initialisation de la plateforme CTI
        self.cti_platform = CyberThreatIntelligence()
        
        # Configuration des routes
        self._setup_routes()
        
        logger.info("Defensive Intelligence Web Platform initialisée")
    
    def _setup_routes(self):
        """Configure les routes de l'API"""
        
        # Routes OSINT
        @self.app.post("/api/osint/missions", response_model=OSINTMissionResponse)
        async def create_osint_mission(mission_data: OSINTMissionCreate):
            """Crée une mission OSINT"""
            try:
                mission = self.cti_platform.create_osint_mission(
                    name=mission_data.name,
                    targets=mission_data.targets,
                    depth=mission_data.depth,
                    frequency=mission_data.frequency
                )
                
                return OSINTMissionResponse(
                    id=mission.id,
                    name=mission.name,
                    targets=mission.targets,
                    depth=mission.depth,
                    frequency=mission.frequency,
                    status=mission.status,
                    created_at=mission.created_at,
                    last_run=mission.last_run,
                    findings_count=mission.findings_count
                )
                
            except Exception as e:
                logger.error(f"Erreur lors de la création de mission OSINT: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/api/osint/missions")
        async def get_osint_missions():
            """Récupère toutes les missions OSINT"""
            try:
                missions = []
                for mission in self.cti_platform.osint_missions.values():
                    missions.append(OSINTMissionResponse(
                        id=mission.id,
                        name=mission.name,
                        targets=mission.targets,
                        depth=mission.depth,
                        frequency=mission.frequency,
                        status=mission.status,
                        created_at=mission.created_at,
                        last_run=mission.last_run,
                        findings_count=mission.findings_count
                    ))
                
                return {"missions": missions}
                
            except Exception as e:
                logger.error(f"Erreur lors de la récupération des missions: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.post("/api/osint/missions/{mission_id}/execute")
        async def execute_osint_mission(mission_id: str):
            """Exécute une mission OSINT"""
            try:
                result = await self.cti_platform.execute_osint_mission(mission_id)
                
                # Notification WebSocket
                await self._broadcast_notification({
                    "type": "mission_executed",
                    "mission_id": mission_id,
                    "findings_count": result.get('findings_count', 0),
                    "timestamp": datetime.utcnow().isoformat()
                })
                
                return result
                
            except Exception as e:
                logger.error(f"Erreur lors de l'exécution de la mission: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        # Routes de détection de menaces
        @self.app.post("/api/detection/threats")
        async def detect_threats(request: ThreatDetectionRequest):
            """Détecte les menaces en temps réel"""
            try:
                detections = self.cti_platform.detect_threats_realtime(request.data)
                
                # Notification WebSocket pour les détections critiques
                critical_detections = [d for d in detections if d.threat_level == ThreatLevel.CRITICAL]
                if critical_detections:
                    await self._broadcast_notification({
                        "type": "critical_threat_detected",
                        "detections_count": len(critical_detections),
                        "timestamp": datetime.utcnow().isoformat()
                    })
                
                return {
                    "detections": [
                        {
                            "id": d.id,
                            "detection_type": d.detection_type.value,
                            "source": d.source,
                            "indicators": d.indicators,
                            "threat_level": d.threat_level.value,
                            "confidence": d.confidence,
                            "context": d.context,
                            "created_at": d.created_at.isoformat(),
                            "investigated": d.investigated,
                            "false_positive": d.false_positive
                        }
                        for d in detections
                    ],
                    "total_detections": len(detections),
                    "critical_detections": len(critical_detections)
                }
                
            except Exception as e:
                logger.error(f"Erreur lors de la détection de menaces: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        # Routes Kanban
        @self.app.get("/api/kanban/board")
        async def get_kanban_board():
            """Récupère l'état du tableau Kanban"""
            try:
                board = self.cti_platform.get_kanban_board()
                return board
                
            except Exception as e:
                logger.error(f"Erreur lors de la récupération du tableau Kanban: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.post("/api/kanban/move")
        async def move_kanban_card(move_data: KanbanCardMove):
            """Déplace une carte Kanban"""
            try:
                result = self.cti_platform.move_kanban_card(
                    move_data.card_id,
                    move_data.from_column,
                    move_data.to_column
                )
                
                # Notification WebSocket
                await self._broadcast_notification({
                    "type": "kanban_card_moved",
                    "card_id": move_data.card_id,
                    "from_column": move_data.from_column,
                    "to_column": move_data.to_column,
                    "timestamp": datetime.utcnow().isoformat()
                })
                
                return result
                
            except Exception as e:
                logger.error(f"Erreur lors du déplacement de carte: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        # Routes de notifications
        @self.app.post("/api/notifications/send")
        async def send_notification(notification: NotificationRequest):
            """Envoie une notification"""
            try:
                # Ajout à la queue de notifications
                self.cti_platform.notification_queue.append({
                    "type": notification.type,
                    "message": notification.message,
                    "recipients": notification.recipients,
                    "timestamp": datetime.utcnow().isoformat()
                })
                
                # Notification WebSocket
                await self._broadcast_notification({
                    "type": "notification_sent",
                    "notification_type": notification.type,
                    "message": notification.message,
                    "timestamp": datetime.utcnow().isoformat()
                })
                
                return {"success": True, "message": "Notification envoyée"}
                
            except Exception as e:
                logger.error(f"Erreur lors de l'envoi de notification: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        # Routes de rapports
        @self.app.get("/api/reports/threat-intelligence")
        async def get_threat_intelligence_report():
            """Génère un rapport de threat intelligence"""
            try:
                report = self.cti_platform.generate_threat_intelligence_report()
                return report
                
            except Exception as e:
                logger.error(f"Erreur lors de la génération du rapport: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        # Routes de statistiques
        @self.app.get("/api/stats/dashboard")
        async def get_dashboard_stats():
            """Récupère les statistiques du dashboard"""
            try:
                # Statistiques OSINT
                osint_stats = {
                    "total_missions": len(self.cti_platform.osint_missions),
                    "active_missions": len([m for m in self.cti_platform.osint_missions.values() if m.status == 'active']),
                    "total_findings": len(self.cti_platform.osint_findings),
                    "findings_today": len([f for f in self.cti_platform.osint_findings 
                                         if f.created_at.date() == datetime.utcnow().date()])
                }
                
                # Statistiques de détection
                detection_stats = {
                    "total_detections": len(self.cti_platform.threat_detections),
                    "detections_today": len([d for d in self.cti_platform.threat_detections 
                                          if d.created_at.date() == datetime.utcnow().date()]),
                    "critical_detections": len([d for d in self.cti_platform.threat_detections 
                                             if d.threat_level == ThreatLevel.CRITICAL]),
                    "investigated_detections": len([d for d in self.cti_platform.threat_detections if d.investigated])
                }
                
                # Statistiques Kanban
                kanban_stats = {
                    "total_cards": sum(len(column) for column in self.cti_platform.kanban_board.values()),
                    "to_validate": len(self.cti_platform.kanban_board['to_validate']),
                    "in_progress": len(self.cti_platform.kanban_board['in_progress']),
                    "validated": len(self.cti_platform.kanban_board['validated']),
                    "expired": len(self.cti_platform.kanban_board['expired'])
                }
                
                return {
                    "osint_statistics": osint_stats,
                    "detection_statistics": detection_stats,
                    "kanban_statistics": kanban_stats,
                    "timestamp": datetime.utcnow().isoformat()
                }
                
            except Exception as e:
                logger.error(f"Erreur lors de la récupération des statistiques: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        # Routes de santé
        @self.app.get("/api/health")
        async def health_check():
            """Vérification de santé de l'API"""
            return {
                "status": "healthy",
                "timestamp": datetime.utcnow().isoformat(),
                "version": "1.0.0"
            }
        
        # WebSocket pour les notifications en temps réel
        @self.app.websocket("/ws")
        async def websocket_endpoint(websocket: WebSocket):
            """WebSocket pour les notifications en temps réel"""
            await websocket.accept()
            self.active_connections.append(websocket)
            
            try:
                while True:
                    # Écoute des messages du client
                    data = await websocket.receive_text()
                    message = json.loads(data)
                    
                    # Traitement des messages
                    if message.get("type") == "ping":
                        await websocket.send_text(json.dumps({"type": "pong", "timestamp": datetime.utcnow().isoformat()}))
                    
            except WebSocketDisconnect:
                self.active_connections.remove(websocket)
            except Exception as e:
                logger.error(f"Erreur WebSocket: {e}")
                if websocket in self.active_connections:
                    self.active_connections.remove(websocket)
    
    async def _broadcast_notification(self, notification: Dict[str, Any]):
        """Diffuse une notification à tous les clients WebSocket connectés"""
        try:
            message = json.dumps(notification)
            disconnected = []
            
            for connection in self.active_connections:
                try:
                    await connection.send_text(message)
                except:
                    disconnected.append(connection)
            
            # Nettoyage des connexions fermées
            for connection in disconnected:
                if connection in self.active_connections:
                    self.active_connections.remove(connection)
                    
        except Exception as e:
            logger.error(f"Erreur lors de la diffusion de notification: {e}")
    
    def run(self, host: str = "0.0.0.0", port: int = 8000, debug: bool = False):
        """Lance le serveur web"""
        try:
            logger.info(f"Démarrage du serveur Defensive Intelligence sur {host}:{port}")
            uvicorn.run(
                self.app,
                host=host,
                port=port,
                log_level="debug" if debug else "info"
            )
        except Exception as e:
            logger.error(f"Erreur lors du démarrage du serveur: {e}")
            raise

# Interface de gestion des playbooks SOC
class SOCPlaybookManager:
    """Gestionnaire de playbooks SOC"""
    
    def __init__(self, cti_platform: CyberThreatIntelligence):
        self.cti_platform = cti_platform
        self.playbooks = {}
        self._initialize_default_playbooks()
    
    def _initialize_default_playbooks(self):
        """Initialise les playbooks par défaut"""
        self.playbooks = {
            "incident_response": {
                "name": "Incident Response Playbook",
                "description": "Playbook de réponse aux incidents de sécurité",
                "steps": [
                    "Détection et classification de l'incident",
                    "Containment immédiat",
                    "Investigation approfondie",
                    "Éradication de la menace",
                    "Récupération des systèmes",
                    "Post-mortem et amélioration"
                ],
                "automated_actions": [
                    "Isolation automatique des systèmes compromis",
                    "Notification des équipes de sécurité",
                    "Collecte automatique des preuves",
                    "Mise à jour des règles de détection"
                ]
            },
            "threat_hunting": {
                "name": "Threat Hunting Playbook",
                "description": "Playbook de chasse aux menaces",
                "steps": [
                    "Définition des hypothèses de menace",
                    "Collecte et analyse des données",
                    "Corrélation des indicateurs",
                    "Validation des hypothèses",
                    "Documentation des findings"
                ],
                "automated_actions": [
                    "Exécution automatique des requêtes de chasse",
                    "Corrélation des logs multi-sources",
                    "Génération d'alertes pour les anomalies",
                    "Mise à jour des règles de détection"
                ]
            },
            "osint_investigation": {
                "name": "OSINT Investigation Playbook",
                "description": "Playbook d'investigation OSINT",
                "steps": [
                    "Définition du périmètre d'investigation",
                    "Collecte automatisée des données publiques",
                    "Analyse et corrélation des informations",
                    "Validation et vérification des sources",
                    "Rapport d'investigation"
                ],
                "automated_actions": [
                    "Lancement automatique des missions OSINT",
                    "Analyse automatique des findings",
                    "Corrélation avec les bases de données internes",
                    "Génération de rapports d'investigation"
                ]
            }
        }
    
    def get_playbook(self, playbook_id: str) -> Dict[str, Any]:
        """Récupère un playbook"""
        return self.playbooks.get(playbook_id, {})
    
    def execute_playbook(self, playbook_id: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Exécute un playbook"""
        try:
            playbook = self.get_playbook(playbook_id)
            if not playbook:
                return {"success": False, "error": "Playbook non trouvé"}
            
            # Exécution des actions automatisées
            automated_results = []
            for action in playbook.get("automated_actions", []):
                result = self._execute_automated_action(action, context)
                automated_results.append(result)
            
            return {
                "success": True,
                "playbook_id": playbook_id,
                "playbook_name": playbook.get("name", ""),
                "automated_results": automated_results,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de l'exécution du playbook: {e}")
            return {"success": False, "error": str(e)}
    
    def _execute_automated_action(self, action: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Exécute une action automatisée"""
        try:
            if "isolation automatique" in action.lower():
                # Simulation d'isolation automatique
                return {"action": action, "status": "executed", "result": "Systems isolated"}
            
            elif "notification" in action.lower():
                # Simulation de notification
                return {"action": action, "status": "executed", "result": "Notifications sent"}
            
            elif "collecte automatique" in action.lower():
                # Simulation de collecte automatique
                return {"action": action, "status": "executed", "result": "Evidence collected"}
            
            elif "lancement automatique" in action.lower():
                # Simulation de lancement de mission OSINT
                return {"action": action, "status": "executed", "result": "OSINT mission launched"}
            
            else:
                return {"action": action, "status": "skipped", "result": "Action not implemented"}
                
        except Exception as e:
            logger.error(f"Erreur lors de l'exécution de l'action: {e}")
            return {"action": action, "status": "error", "result": str(e)}

# Interface de gestion des workflows collaboratifs
class CollaborativeWorkflowManager:
    """Gestionnaire de workflows collaboratifs"""
    
    def __init__(self, cti_platform: CyberThreatIntelligence):
        self.cti_platform = cti_platform
        self.workflows = {}
        self._initialize_workflows()
    
    def _initialize_workflows(self):
        """Initialise les workflows collaboratifs"""
        self.workflows = {
            "threat_validation": {
                "name": "Threat Validation Workflow",
                "description": "Workflow de validation des menaces détectées",
                "stages": [
                    {"name": "Initial Detection", "assignee": "system", "auto": True},
                    {"name": "Analyst Review", "assignee": "analyst", "auto": False},
                    {"name": "Senior Review", "assignee": "senior_analyst", "auto": False},
                    {"name": "Final Validation", "assignee": "team_lead", "auto": False}
                ],
                "escalation_rules": {
                    "timeout": 3600,  # 1 heure
                    "escalation_to": "senior_analyst"
                }
            },
            "incident_investigation": {
                "name": "Incident Investigation Workflow",
                "description": "Workflow d'investigation d'incidents",
                "stages": [
                    {"name": "Incident Creation", "assignee": "system", "auto": True},
                    {"name": "Initial Assessment", "assignee": "analyst", "auto": False},
                    {"name": "Deep Investigation", "assignee": "senior_analyst", "auto": False},
                    {"name": "Resolution", "assignee": "team_lead", "auto": False}
                ],
                "escalation_rules": {
                    "timeout": 7200,  # 2 heures
                    "escalation_to": "team_lead"
                }
            }
        }
    
    def get_workflow(self, workflow_id: str) -> Dict[str, Any]:
        """Récupère un workflow"""
        return self.workflows.get(workflow_id, {})
    
    def start_workflow(self, workflow_id: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Démarre un workflow"""
        try:
            workflow = self.get_workflow(workflow_id)
            if not workflow:
                return {"success": False, "error": "Workflow non trouvé"}
            
            # Création de l'instance de workflow
            workflow_instance = {
                "id": f"workflow_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
                "workflow_id": workflow_id,
                "status": "active",
                "current_stage": 0,
                "context": context,
                "created_at": datetime.utcnow().isoformat(),
                "stages_completed": []
            }
            
            # Exécution de la première étape
            first_stage = workflow["stages"][0]
            if first_stage["auto"]:
                result = self._execute_stage(first_stage, context)
                workflow_instance["stages_completed"].append({
                    "stage": first_stage["name"],
                    "result": result,
                    "completed_at": datetime.utcnow().isoformat()
                })
                workflow_instance["current_stage"] = 1
            
            return {
                "success": True,
                "workflow_instance": workflow_instance,
                "next_stage": workflow["stages"][workflow_instance["current_stage"]] if workflow_instance["current_stage"] < len(workflow["stages"]) else None
            }
            
        except Exception as e:
            logger.error(f"Erreur lors du démarrage du workflow: {e}")
            return {"success": False, "error": str(e)}
    
    def _execute_stage(self, stage: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Exécute une étape du workflow"""
        try:
            # Simulation d'exécution d'étape
            return {
                "stage_name": stage["name"],
                "assignee": stage["assignee"],
                "status": "completed",
                "result": f"Stage {stage['name']} executed successfully",
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de l'exécution de l'étape: {e}")
            return {"status": "error", "result": str(e)}

# Point d'entrée principal
def create_app() -> FastAPI:
    """Crée l'application FastAPI"""
    web_platform = DefensiveIntelligenceWeb()
    return web_platform.app

if __name__ == "__main__":
    # Création et lancement de l'application
    web_platform = DefensiveIntelligenceWeb()
    web_platform.run(host="0.0.0.0", port=8000, debug=True)
