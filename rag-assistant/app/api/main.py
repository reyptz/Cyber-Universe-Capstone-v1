"""
Application FastAPI pour l'assistant RAG sécurisé
"""
import logging
import os
from typing import Optional, Dict, Any
from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from contextlib import asynccontextmanager

from ..core.rag_chain import SecureRAGChain
from ..security.governance import SecurityGovernance
from ..config import config

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Instance globale de la chaîne RAG
rag_chain: Optional[SecureRAGChain] = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Gestionnaire de cycle de vie de l'application"""
    global rag_chain
    
    # Initialisation
    logger.info("Initialisation de l'assistant RAG sécurisé...")
    try:
        rag_chain = SecureRAGChain(
            docs_directory="docs",
            openai_api_key=os.getenv("OPENAI_API_KEY")
        )
        
        # Chargement des documents
        load_result = rag_chain.load_and_process_documents()
        if load_result.get('success', False):
            logger.info(f"Documents chargés avec succès: {load_result['processed_documents']} documents traités")
        else:
            logger.warning(f"Problème lors du chargement des documents: {load_result.get('error', 'Erreur inconnue')}")
        
        logger.info("Assistant RAG sécurisé initialisé avec succès")
        
    except Exception as e:
        logger.error(f"Erreur lors de l'initialisation: {e}")
        raise
    
    yield
    
    # Nettoyage
    logger.info("Arrêt de l'assistant RAG sécurisé...")

# Création de l'application FastAPI
app = FastAPI(
    title="Assistant RAG Sécurisé",
    description="Assistant RAG avec sécurité de bout en bout pour PME Mali",
    version="1.0.0",
    lifespan=lifespan
)

# Configuration CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # En production, spécifier les domaines autorisés
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Modèles Pydantic
class QueryRequest(BaseModel):
    query: str
    user_id: Optional[str] = None

class QueryResponse(BaseModel):
    success: bool
    answer: Optional[str] = None
    error: Optional[str] = None
    security_analysis: Optional[Dict[str, Any]] = None
    response_analysis: Optional[Dict[str, Any]] = None

class SecurityStatusResponse(BaseModel):
    system_status: str
    quarantine_status: Dict[str, Any]
    mttd_mttr_metrics: Dict[str, Any]
    supply_chain_risks: Dict[str, Any]
    prioritized_findings: list
    security_timestamp: str

class SecurityReportResponse(BaseModel):
    report_generated: bool
    report: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

# Dépendances
def get_rag_chain() -> SecureRAGChain:
    """Dépendance pour obtenir l'instance de la chaîne RAG"""
    if rag_chain is None:
        raise HTTPException(status_code=503, detail="Chaîne RAG non initialisée")
    return rag_chain

# Routes de l'API
@app.get("/")
async def root():
    """Point d'entrée principal"""
    return {
        "message": "Assistant RAG Sécurisé - PME Mali",
        "version": "1.0.0",
        "status": "operational",
        "security_features": [
            "Filtrage PII",
            "Modération de contenu",
            "Détection d'injection de prompts",
            "Détection de secrets",
            "Sécurité des embeddings",
            "Surveillance adversarial",
            "Gouvernance des risques"
        ]
    }

@app.get("/health")
async def health_check():
    """Vérification de santé du système"""
    try:
        if rag_chain is None:
            return {"status": "unhealthy", "reason": "Chaîne RAG non initialisée"}
        
        security_status = rag_chain.get_security_status()
        return {
            "status": "healthy",
            "system_status": security_status.get("system_status", "unknown"),
            "security_timestamp": security_status.get("security_timestamp")
        }
    except Exception as e:
        logger.error(f"Erreur lors de la vérification de santé: {e}")
        return {"status": "unhealthy", "reason": str(e)}

@app.post("/query", response_model=QueryResponse)
async def secure_query(
    request: QueryRequest,
    background_tasks: BackgroundTasks,
    rag: SecureRAGChain = Depends(get_rag_chain)
):
    """
    Exécute une requête sécurisée sur l'assistant RAG
    
    Args:
        request: Requête contenant la question et l'ID utilisateur
        background_tasks: Tâches en arrière-plan
        rag: Instance de la chaîne RAG
    
    Returns:
        Réponse sécurisée de l'assistant
    """
    try:
        logger.info(f"Requête reçue de l'utilisateur {request.user_id}: {request.query[:100]}...")
        
        # Exécution de la requête sécurisée
        result = rag.secure_query(request.query, request.user_id)
        
        # Tâche en arrière-plan pour l'audit
        background_tasks.add_task(log_query_audit, request, result)
        
        return QueryResponse(**result)
        
    except Exception as e:
        logger.error(f"Erreur lors de l'exécution de la requête: {e}")
        raise HTTPException(status_code=500, detail=f"Erreur interne: {str(e)}")

@app.get("/security/status", response_model=SecurityStatusResponse)
async def get_security_status(rag: SecureRAGChain = Depends(get_rag_chain)):
    """
    Retourne le statut de sécurité du système
    
    Returns:
        Statut de sécurité complet
    """
    try:
        security_status = rag.get_security_status()
        return SecurityStatusResponse(**security_status)
    except Exception as e:
        logger.error(f"Erreur lors de la récupération du statut de sécurité: {e}")
        raise HTTPException(status_code=500, detail=f"Erreur interne: {str(e)}")

@app.get("/security/report", response_model=SecurityReportResponse)
async def generate_security_report(rag: SecureRAGChain = Depends(get_rag_chain)):
    """
    Génère un rapport de sécurité complet
    
    Returns:
        Rapport de sécurité
    """
    try:
        report = rag.generate_security_report()
        return SecurityReportResponse(**report)
    except Exception as e:
        logger.error(f"Erreur lors de la génération du rapport de sécurité: {e}")
        raise HTTPException(status_code=500, detail=f"Erreur interne: {str(e)}")

@app.post("/security/quarantine/release/{content_id}")
async def release_from_quarantine(
    content_id: str,
    human_approval: bool = False,
    rag: SecureRAGChain = Depends(get_rag_chain)
):
    """
    Libère du contenu de la quarantaine
    
    Args:
        content_id: Identifiant du contenu à libérer
        human_approval: Approbation humaine
    
    Returns:
        Résultat de la libération
    """
    try:
        result = rag.adversarial_detector.release_from_quarantine(content_id, human_approval)
        return result
    except Exception as e:
        logger.error(f"Erreur lors de la libération de quarantaine: {e}")
        raise HTTPException(status_code=500, detail=f"Erreur interne: {str(e)}")

@app.get("/security/quarantine/status")
async def get_quarantine_status(rag: SecureRAGChain = Depends(get_rag_chain)):
    """
    Retourne le statut de la quarantaine
    
    Returns:
        Statut de la quarantaine
    """
    try:
        status = rag.adversarial_detector.get_quarantine_status()
        return status
    except Exception as e:
        logger.error(f"Erreur lors de la récupération du statut de quarantaine: {e}")
        raise HTTPException(status_code=500, detail=f"Erreur interne: {str(e)}")

@app.get("/security/supply-chain/status")
async def get_supply_chain_status(rag: SecureRAGChain = Depends(get_rag_chain)):
    """
    Retourne le statut de la chaîne d'approvisionnement
    
    Returns:
        Statut de la chaîne d'approvisionnement
    """
    try:
        status = rag.supply_chain_security.monitor_supply_chain_risks()
        return status
    except Exception as e:
        logger.error(f"Erreur lors de la récupération du statut de la chaîne d'approvisionnement: {e}")
        raise HTTPException(status_code=500, detail=f"Erreur interne: {str(e)}")

@app.get("/security/findings/prioritized")
async def get_prioritized_findings(rag: SecureRAGChain = Depends(get_rag_chain)):
    """
    Retourne les findings de sécurité priorisés
    
    Returns:
        Liste des findings priorisés
    """
    try:
        findings = rag.governance.prioritize_findings()
        return {"findings": findings}
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des findings priorisés: {e}")
        raise HTTPException(status_code=500, detail=f"Erreur interne: {str(e)}")

@app.get("/security/metrics/mttd-mttr")
async def get_mttd_mttr_metrics(rag: SecureRAGChain = Depends(get_rag_chain)):
    """
    Retourne les métriques MTTD/MTTR
    
    Returns:
        Métriques MTTD/MTTR
    """
    try:
        metrics = rag.governance.calculate_mttd_mttr()
        return metrics
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des métriques MTTD/MTTR: {e}")
        raise HTTPException(status_code=500, detail=f"Erreur interne: {str(e)}")

# Fonctions utilitaires
async def log_query_audit(request: QueryRequest, result: Dict[str, Any]):
    """Enregistre l'audit de la requête en arrière-plan"""
    try:
        audit_log = {
            "timestamp": rag_chain._get_timestamp() if rag_chain else "unknown",
            "user_id": request.user_id,
            "query_length": len(request.query),
            "success": result.get("success", False),
            "security_analysis": result.get("security_analysis", {}),
            "response_analysis": result.get("response_analysis", {})
        }
        
        # En production, enregistrer dans une base de données d'audit
        logger.info(f"Audit de requête: {audit_log}")
        
    except Exception as e:
        logger.error(f"Erreur lors de l'audit de requête: {e}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
