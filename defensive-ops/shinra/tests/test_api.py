"""
Test suite for Shinra OSINT Agent API
"""

import pytest
from fastapi.testclient import TestClient
from datetime import datetime

from api.main import app

client = TestClient(app)

# ============================================================================
# Authentication Tests
# ============================================================================

def test_login_success():
    """Test successful login"""
    response = client.post(
        "/api/auth/token",
        data={"username": "admin", "password": "admin"}
    )
    assert response.status_code == 200
    assert "access_token" in response.json()
    assert response.json()["token_type"] == "bearer"

def test_login_failure():
    """Test failed login with wrong credentials"""
    response = client.post(
        "/api/auth/token",
        data={"username": "wrong", "password": "wrong"}
    )
    assert response.status_code == 401

# ============================================================================
# Mission Tests
# ============================================================================

@pytest.fixture
def auth_headers():
    """Get authentication headers"""
    response = client.post(
        "/api/auth/token",
        data={"username": "admin", "password": "admin"}
    )
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

def test_create_mission(auth_headers):
    """Test mission creation"""
    mission_data = {
        "name": "Test Mission",
        "targets": ["https://example.com"],
        "depth": 3,
        "frequency": "once",
        "crawler_modules": ["http"],
        "tags": ["test"]
    }
    
    response = client.post(
        "/api/missions",
        json=mission_data,
        headers=auth_headers
    )
    
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "Test Mission"
    assert data["status"] == "pending"
    assert "id" in data

def test_list_missions(auth_headers):
    """Test listing missions"""
    response = client.get("/api/missions", headers=auth_headers)
    assert response.status_code == 200
    assert isinstance(response.json(), list)

def test_get_mission(auth_headers):
    """Test getting a specific mission"""
    # First create a mission
    mission_data = {
        "name": "Get Test Mission",
        "targets": ["https://example.com"],
        "depth": 2,
        "crawler_modules": ["http"]
    }
    
    create_response = client.post(
        "/api/missions",
        json=mission_data,
        headers=auth_headers
    )
    mission_id = create_response.json()["id"]
    
    # Then get it
    response = client.get(f"/api/missions/{mission_id}", headers=auth_headers)
    assert response.status_code == 200
    assert response.json()["id"] == mission_id

def test_get_mission_not_found(auth_headers):
    """Test getting non-existent mission"""
    response = client.get("/api/missions/nonexistent", headers=auth_headers)
    assert response.status_code == 404

# ============================================================================
# RAG Tests
# ============================================================================

def test_rag_query(auth_headers):
    """Test RAG query"""
    query_data = {
        "query": "security vulnerabilities",
        "top_k": 10,
        "include_analysis": True
    }
    
    response = client.post(
        "/api/rag/query",
        json=query_data,
        headers=auth_headers
    )
    
    assert response.status_code == 200
    data = response.json()
    assert data["query"] == "security vulnerabilities"
    assert "results" in data
    assert "analysis" in data

# ============================================================================
# Workflow Tests
# ============================================================================

def test_list_workflow_items(auth_headers):
    """Test listing workflow items"""
    response = client.get("/api/workflow/items", headers=auth_headers)
    assert response.status_code == 200
    assert isinstance(response.json(), list)

def test_list_workflow_items_with_status_filter(auth_headers):
    """Test listing workflow items with status filter"""
    response = client.get(
        "/api/workflow/items?status=to_validate",
        headers=auth_headers
    )
    assert response.status_code == 200

# ============================================================================
# Health & Metrics Tests
# ============================================================================

def test_health_check():
    """Test health check endpoint"""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "version" in data
    assert "components" in data

def test_metrics(auth_headers):
    """Test metrics endpoint"""
    response = client.get("/api/metrics", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert "missions" in data
    assert "results" in data
    assert "workflow" in data
    assert "detection" in data

# ============================================================================
# Performance Tests
# ============================================================================

def test_api_response_time(auth_headers):
    """Test API response time"""
    import time
    
    start = time.time()
    response = client.get("/api/health")
    elapsed = (time.time() - start) * 1000  # Convert to ms
    
    assert response.status_code == 200
    assert elapsed < 100  # Should respond in < 100ms

@pytest.mark.benchmark
def test_mission_creation_performance(auth_headers, benchmark):
    """Benchmark mission creation"""
    mission_data = {
        "name": "Benchmark Mission",
        "targets": ["https://example.com"],
        "depth": 1,
        "crawler_modules": ["http"]
    }
    
    def create_mission():
        return client.post(
            "/api/missions",
            json=mission_data,
            headers=auth_headers
        )
    
    result = benchmark(create_mission)
    assert result.status_code == 201

# ============================================================================
# Security Tests
# ============================================================================

def test_unauthorized_access():
    """Test accessing protected endpoint without auth"""
    response = client.get("/api/missions")
    assert response.status_code == 401

def test_cors_headers():
    """Test CORS headers are present"""
    response = client.options("/api/missions")
    assert "access-control-allow-origin" in response.headers

# ============================================================================
# Run Tests
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
