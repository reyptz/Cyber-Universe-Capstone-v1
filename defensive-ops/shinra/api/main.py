"""
Shinra OSINT Agent - FastAPI Backend
Collecte OSINT avec crawlers modulables, RAG et workflow collaboratif
"""

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from enum import Enum
import asyncio
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("shinra")

# FastAPI app
app = FastAPI(
    title="Shinra OSINT Agent",
    description="Plateforme de collecte OSINT avec RAG et workflow collaboratif",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# OAuth2 configuration
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/token")

# ============================================================================
# Models
# ============================================================================

class MissionStatus(str, Enum):
    """Mission status enumeration"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED = "paused"

class CrawlerType(str, Enum):
    """Crawler module types"""
    HTTP = "http"
    API = "api"
    JAVASCRIPT = "javascript"
    SOCIAL_MEDIA = "social_media"
    FORUM = "forum"

class WorkflowStatus(str, Enum):
    """Workflow column status"""
    TO_VALIDATE = "to_validate"
    IN_PROGRESS = "in_progress"
    VALIDATED = "validated"
    EXPIRED = "expired"

class MissionCreate(BaseModel):
    """Mission creation request"""
    name: str = Field(..., description="Mission name")
    targets: List[str] = Field(..., description="Target URLs or identifiers")
    depth: int = Field(default=3, ge=1, le=10, description="Crawl depth")
    frequency: Optional[str] = Field(default="once", description="Crawl frequency")
    crawler_modules: List[CrawlerType] = Field(default=[CrawlerType.HTTP])
    tags: Optional[List[str]] = Field(default=[])

class Mission(BaseModel):
    """Mission model"""
    id: str
    name: str
    targets: List[str]
    depth: int
    frequency: str
    crawler_modules: List[CrawlerType]
    status: MissionStatus
    created_at: datetime
    updated_at: datetime
    tags: List[str]
    results_count: int = 0
    
class CrawlResult(BaseModel):
    """Crawl result model"""
    id: str
    mission_id: str
    url: str
    content: str
    metadata: Dict[str, Any]
    collected_at: datetime
    workflow_status: WorkflowStatus = WorkflowStatus.TO_VALIDATE

class RAGQuery(BaseModel):
    """RAG query request"""
    query: str = Field(..., description="Search query")
    mission_ids: Optional[List[str]] = Field(default=None)
    top_k: int = Field(default=10, ge=1, le=100)
    include_analysis: bool = Field(default=True)

class RAGResponse(BaseModel):
    """RAG query response"""
    query: str
    results: List[Dict[str, Any]]
    analysis: Optional[str] = None
    sources: List[str]

class WorkflowItem(BaseModel):
    """Workflow Kanban item"""
    id: str
    mission_id: str
    title: str
    content: str
    status: WorkflowStatus
    assigned_to: Optional[str] = None
    comments: List[Dict[str, Any]] = []
    created_at: datetime
    updated_at: datetime

class DetectionRule(BaseModel):
    """Detection rule model"""
    id: str
    name: str
    rule_type: str  # sigma, yara, custom
    content: str
    enabled: bool
    tags: List[str]

# ============================================================================
# In-memory storage (replace with MongoDB in production)
# ============================================================================

missions_db: Dict[str, Mission] = {}
crawl_results_db: Dict[str, CrawlResult] = {}
workflow_items_db: Dict[str, WorkflowItem] = {}
detection_rules_db: Dict[str, DetectionRule] = {}

# ============================================================================
# Authentication
# ============================================================================

@app.post("/api/auth/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    OAuth2 password grant authentication
    """
    # Placeholder - implement proper authentication
    if form_data.username == "admin" and form_data.password == "admin":
        return {
            "access_token": "fake-jwt-token",
            "token_type": "bearer"
        }
    raise HTTPException(status_code=401, detail="Invalid credentials")

async def get_current_user(token: str = Depends(oauth2_scheme)):
    """
    Get current authenticated user
    """
    # Placeholder - implement proper JWT validation
    return {"username": "admin", "role": "analyst"}

# ============================================================================
# Mission Management Endpoints
# ============================================================================

@app.post("/api/missions", response_model=Mission, status_code=201)
async def create_mission(
    mission: MissionCreate,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
):
    """
    Create a new OSINT mission (F1)
    """
    import uuid
    
    mission_id = str(uuid.uuid4())
    now = datetime.utcnow()
    
    new_mission = Mission(
        id=mission_id,
        name=mission.name,
        targets=mission.targets,
        depth=mission.depth,
        frequency=mission.frequency,
        crawler_modules=mission.crawler_modules,
        status=MissionStatus.PENDING,
        created_at=now,
        updated_at=now,
        tags=mission.tags or [],
        results_count=0
    )
    
    missions_db[mission_id] = new_mission
    
    # Start crawling in background (F2)
    background_tasks.add_task(start_crawling, mission_id)
    
    logger.info(f"Created mission {mission_id}: {mission.name}")
    
    return new_mission

@app.get("/api/missions", response_model=List[Mission])
async def list_missions(
    status: Optional[MissionStatus] = None,
    current_user: dict = Depends(get_current_user)
):
    """
    List all missions with optional status filter
    """
    missions = list(missions_db.values())
    
    if status:
        missions = [m for m in missions if m.status == status]
    
    return missions

@app.get("/api/missions/{mission_id}", response_model=Mission)
async def get_mission(
    mission_id: str,
    current_user: dict = Depends(get_current_user)
):
    """
    Get mission details
    """
    if mission_id not in missions_db:
        raise HTTPException(status_code=404, detail="Mission not found")
    
    return missions_db[mission_id]

@app.put("/api/missions/{mission_id}/status")
async def update_mission_status(
    mission_id: str,
    status: MissionStatus,
    current_user: dict = Depends(get_current_user)
):
    """
    Update mission status (pause, resume, stop)
    """
    if mission_id not in missions_db:
        raise HTTPException(status_code=404, detail="Mission not found")
    
    mission = missions_db[mission_id]
    mission.status = status
    mission.updated_at = datetime.utcnow()
    
    logger.info(f"Updated mission {mission_id} status to {status}")
    
    return {"status": "success", "mission_id": mission_id, "new_status": status}

# ============================================================================
# Crawling & Collection (F2)
# ============================================================================

async def start_crawling(mission_id: str):
    """
    Background task to start crawling for a mission
    """
    logger.info(f"Starting crawl for mission {mission_id}")
    
    mission = missions_db.get(mission_id)
    if not mission:
        logger.error(f"Mission {mission_id} not found")
        return
    
    mission.status = MissionStatus.RUNNING
    mission.updated_at = datetime.utcnow()
    
    # Simulate crawling (replace with actual crawler implementation)
    await asyncio.sleep(2)
    
    # Create dummy results
    import uuid
    for i, target in enumerate(mission.targets):
        result_id = str(uuid.uuid4())
        result = CrawlResult(
            id=result_id,
            mission_id=mission_id,
            url=target,
            content=f"Collected content from {target}",
            metadata={
                "crawler_type": mission.crawler_modules[0].value,
                "response_code": 200,
                "content_length": 1024
            },
            collected_at=datetime.utcnow()
        )
        crawl_results_db[result_id] = result
        mission.results_count += 1
    
    mission.status = MissionStatus.COMPLETED
    mission.updated_at = datetime.utcnow()
    
    logger.info(f"Completed crawl for mission {mission_id}: {mission.results_count} results")

@app.get("/api/missions/{mission_id}/results", response_model=List[CrawlResult])
async def get_mission_results(
    mission_id: str,
    skip: int = 0,
    limit: int = 100,
    current_user: dict = Depends(get_current_user)
):
    """
    Get crawl results for a mission
    """
    if mission_id not in missions_db:
        raise HTTPException(status_code=404, detail="Mission not found")
    
    results = [r for r in crawl_results_db.values() if r.mission_id == mission_id]
    return results[skip:skip+limit]

# ============================================================================
# RAG Endpoints (F3)
# ============================================================================

@app.post("/api/rag/query", response_model=RAGResponse)
async def rag_query(
    query: RAGQuery,
    current_user: dict = Depends(get_current_user)
):
    """
    Query RAG system for enriched search (F3)
    """
    logger.info(f"RAG query: {query.query}")
    
    # Placeholder - implement actual RAG with Pinecone/Chroma + LangChain
    results = []
    sources = []
    
    for result in list(crawl_results_db.values())[:query.top_k]:
        if query.mission_ids and result.mission_id not in query.mission_ids:
            continue
            
        results.append({
            "id": result.id,
            "url": result.url,
            "content_preview": result.content[:200],
            "relevance_score": 0.95,
            "collected_at": result.collected_at.isoformat()
        })
        sources.append(result.url)
    
    analysis = None
    if query.include_analysis:
        analysis = f"Analysis for query '{query.query}': Found {len(results)} relevant results."
    
    return RAGResponse(
        query=query.query,
        results=results,
        analysis=analysis,
        sources=sources
    )

# ============================================================================
# Workflow Kanban (F4)
# ============================================================================

@app.get("/api/workflow/items", response_model=List[WorkflowItem])
async def list_workflow_items(
    status: Optional[WorkflowStatus] = None,
    mission_id: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """
    List workflow items with optional filters (F4)
    """
    items = list(workflow_items_db.values())
    
    if status:
        items = [i for i in items if i.status == status]
    
    if mission_id:
        items = [i for i in items if i.mission_id == mission_id]
    
    return items

@app.put("/api/workflow/items/{item_id}")
async def update_workflow_item(
    item_id: str,
    status: Optional[WorkflowStatus] = None,
    assigned_to: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """
    Update workflow item (drag-and-drop, assignment)
    """
    if item_id not in workflow_items_db:
        raise HTTPException(status_code=404, detail="Workflow item not found")
    
    item = workflow_items_db[item_id]
    
    if status:
        item.status = status
    if assigned_to:
        item.assigned_to = assigned_to
    
    item.updated_at = datetime.utcnow()
    
    return {"status": "success", "item_id": item_id}

@app.post("/api/workflow/items/{item_id}/comments")
async def add_comment(
    item_id: str,
    comment: str,
    current_user: dict = Depends(get_current_user)
):
    """
    Add comment to workflow item
    """
    if item_id not in workflow_items_db:
        raise HTTPException(status_code=404, detail="Workflow item not found")
    
    item = workflow_items_db[item_id]
    item.comments.append({
        "user": current_user["username"],
        "text": comment,
        "timestamp": datetime.utcnow().isoformat()
    })
    
    return {"status": "success", "comment_count": len(item.comments)}

# ============================================================================
# Detection Rules (F5)
# ============================================================================

@app.get("/api/detection/rules", response_model=List[DetectionRule])
async def list_detection_rules(
    rule_type: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """
    List detection rules
    """
    rules = list(detection_rules_db.values())
    
    if rule_type:
        rules = [r for r in rules if r.rule_type == rule_type]
    
    return rules

# ============================================================================
# Health & Metrics
# ============================================================================

@app.get("/api/health")
async def health_check():
    """
    Health check endpoint
    """
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0",
        "components": {
            "api": "operational",
            "crawlers": "operational",
            "rag": "operational",
            "workflow": "operational"
        }
    }

@app.get("/api/metrics")
async def get_metrics(current_user: dict = Depends(get_current_user)):
    """
    Get platform metrics
    """
    return {
        "missions": {
            "total": len(missions_db),
            "active": len([m for m in missions_db.values() if m.status == MissionStatus.RUNNING]),
            "completed": len([m for m in missions_db.values() if m.status == MissionStatus.COMPLETED])
        },
        "results": {
            "total": len(crawl_results_db),
            "to_validate": len([r for r in crawl_results_db.values() if r.workflow_status == WorkflowStatus.TO_VALIDATE])
        },
        "workflow": {
            "total_items": len(workflow_items_db),
            "in_progress": len([i for i in workflow_items_db.values() if i.status == WorkflowStatus.IN_PROGRESS])
        },
        "detection": {
            "rules_count": len(detection_rules_db),
            "enabled_rules": len([r for r in detection_rules_db.values() if r.enabled])
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
