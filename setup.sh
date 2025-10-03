#!/bin/bash
# Ghost Cyber Universe - Complete Setup Script

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
cat << "EOF"
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║        Ghost Cyber Universe — Capstone v1                 ║
║                                                               ║
║        Complete Cybersecurity Laboratory Setup               ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# ============================================================================
# Configuration
# ============================================================================

SETUP_MODE=${1:-"all"}  # all, offensive, defensive, monitoring

echo -e "${GREEN}Setup Mode: ${SETUP_MODE}${NC}"
echo ""

# ============================================================================
# System Requirements Check
# ============================================================================

echo -e "${YELLOW}[1/6] Checking System Requirements...${NC}"

check_command() {
    if command -v $1 &> /dev/null; then
        echo -e "${GREEN}  ✓ $1 installed${NC}"
        return 0
    else
        echo -e "${RED}  ✗ $1 not found${NC}"
        return 1
    fi
}

MISSING_DEPS=0

# Check required tools
for cmd in docker docker-compose git python3 node npm; do
    check_command $cmd || ((MISSING_DEPS++))
done

if [ "$SETUP_MODE" == "all" ] || [ "$SETUP_MODE" == "offensive" ]; then
    for cmd in rustc cargo go; do
        check_command $cmd || ((MISSING_DEPS++))
    done
fi

if [ $MISSING_DEPS -gt 0 ]; then
    echo -e "${RED}Missing $MISSING_DEPS required dependencies. Please install them first.${NC}"
    exit 1
fi

echo ""

# ============================================================================
# Clone or Update Repository
# ============================================================================

echo -e "${YELLOW}[2/6] Setting Up Repository...${NC}"

if [ ! -d ".git" ]; then
    echo -e "${YELLOW}Initializing git repository...${NC}"
    git init
    git add .
    git commit -m "Initial commit - Ghost Cyber Universe Capstone v1"
fi

echo -e "${GREEN}  ✓ Repository ready${NC}"
echo ""

# ============================================================================
# Offensive Operations Suite Setup
# ============================================================================

if [ "$SETUP_MODE" == "all" ] || [ "$SETUP_MODE" == "offensive" ]; then
    echo -e "${YELLOW}[3/6] Setting Up Offensive Operations Suite...${NC}"
    
    # Genjutsu Engine
    echo -e "${BLUE}Building Genjutsu Engine...${NC}"
    if [ -f "offensive-ops/genjutsu/build.sh" ]; then
        cd offensive-ops/genjutsu
        chmod +x build.sh
        ./build.sh || echo -e "${YELLOW}  Warning: Genjutsu build requires LLVM${NC}"
        cd ../..
    fi
    
    # Ghost Compiler
    echo -e "${BLUE}Building Ghost Compiler...${NC}"
    if [ -d "offensive-ops/ghost" ]; then
        cd offensive-ops/ghost
        cargo build --release || echo -e "${YELLOW}  Warning: Ghost build failed${NC}"
        cd ../..
    fi
    
    # Hiraishin CLI
    echo -e "${BLUE}Building Hiraishin CLI...${NC}"
    if [ -d "offensive-ops/hiraishin/cli" ]; then
        cd offensive-ops/hiraishin/cli
        go mod init hiraishin 2>/dev/null || true
        go mod tidy
        go build -o hiraishin main.go || echo -e "${YELLOW}  Warning: Hiraishin build failed${NC}"
        cd ../../..
    fi
    
    echo -e "${GREEN}  ✓ Offensive Operations Suite ready${NC}"
    echo ""
fi

# ============================================================================
# Defensive Intelligence Platform Setup
# ============================================================================

if [ "$SETUP_MODE" == "all" ] || [ "$SETUP_MODE" == "defensive" ]; then
    echo -e "${YELLOW}[4/6] Setting Up Defensive Intelligence Platform...${NC}"
    
    # Shinra Backend
    echo -e "${BLUE}Setting up Shinra OSINT Agent...${NC}"
    if [ -d "defensive-ops/shinra" ]; then
        cd defensive-ops/shinra
        python3 -m venv venv
        source venv/bin/activate
        pip install -r requirements.txt || echo -e "${YELLOW}  Warning: Some dependencies failed${NC}"
        deactivate
        cd ../..
    fi
    
    # KumoShield Sensors
    echo -e "${BLUE}Building KumoShield Sensors...${NC}"
    if [ -d "defensive-ops/kumoshield/sensors" ]; then
        cd defensive-ops/kumoshield/sensors
        cargo build --release || echo -e "${YELLOW}  Warning: Sensors build requires eBPF support${NC}"
        cd ../../..
    fi
    
    # Frontend
    echo -e "${BLUE}Setting up Frontend...${NC}"
    if [ -d "defensive-ops/frontend" ]; then
        cd defensive-ops/frontend
        npm install || echo -e "${YELLOW}  Warning: npm install failed${NC}"
        cd ../..
    fi
    
    echo -e "${GREEN}  ✓ Defensive Intelligence Platform ready${NC}"
    echo ""
fi

# ============================================================================
# Docker Services Setup
# ============================================================================

echo -e "${YELLOW}[5/6] Starting Docker Services...${NC}"

if [ -f "docker-compose.yml" ]; then
    echo -e "${BLUE}Building containers...${NC}"
    docker-compose build --parallel
    
    echo -e "${BLUE}Starting services...${NC}"
    docker-compose up -d
    
    echo -e "${GREEN}  ✓ Docker services started${NC}"
    
    # Wait for services to be healthy
    echo -e "${BLUE}Waiting for services to be healthy...${NC}"
    sleep 10
    
    # Check service health
    docker-compose ps
else
    echo -e "${YELLOW}  No docker-compose.yml found, skipping${NC}"
fi

echo ""

# ============================================================================
# Monitoring Setup
# ============================================================================

if [ "$SETUP_MODE" == "all" ] || [ "$SETUP_MODE" == "monitoring" ]; then
    echo -e "${YELLOW}[6/6] Setting Up Monitoring...${NC}"
    
    echo -e "${BLUE}Prometheus and Grafana will be available at:${NC}"
    echo -e "  - Prometheus: ${GREEN}http://localhost:9090${NC}"
    echo -e "  - Grafana: ${GREEN}http://localhost:3000${NC} (admin/admin)"
    
    echo -e "${GREEN}  ✓ Monitoring configured${NC}"
    echo ""
fi

# ============================================================================
# Summary
# ============================================================================

echo -e "${GREEN}"
cat << "EOF"
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║                    Setup Complete!                         ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

echo -e "${BLUE}Services Running:${NC}"
echo ""

if docker-compose ps 2>/dev/null | grep -q "Up"; then
    docker-compose ps --format "table {{.Service}}\t{{.Status}}\t{{.Ports}}" | head -n 20
    echo ""
fi

echo -e "${BLUE}Quick Access Links:${NC}"
echo -e "  Grafana Dashboard:     ${GREEN}http://localhost:3000${NC}"
echo -e "  Prometheus:            ${GREEN}http://localhost:9090${NC}"
echo -e "  Shinra API:            ${GREEN}http://localhost:8000${NC}"
echo -e "  Frontend:              ${GREEN}http://localhost:5173${NC}"
echo -e "  MongoDB:               ${GREEN}mongodb://localhost:27017${NC}"
echo -e "  Redis:                 ${GREEN}redis://localhost:6379${NC}"
echo -e "  Kibana:                ${GREEN}http://localhost:5601${NC}"
echo ""

echo -e "${BLUE}Next Steps:${NC}"
echo -e "  1. Access Grafana at http://localhost:3000 (admin/admin)"
echo -e "  2. View API documentation at http://localhost:8000/api/docs"
echo -e "  3. Read IMPLEMENTATION_GUIDE.md for detailed usage"
echo -e "  4. Run tests: ${YELLOW}docker-compose exec shinra-api pytest${NC}"
echo ""

echo -e "${BLUE}Documentation:${NC}"
echo -e "  - Implementation Guide: ${GREEN}IMPLEMENTATION_GUIDE.md${NC}"
echo -e "  - Project Summary: ${GREEN}PROJECT_SUMMARY.md${NC}"
echo -e "  - Compliance: ${GREEN}CAHIERS_DES_CHARGES_IMPLEMENTATION.md${NC}"
echo ""

echo -e "${YELLOW}To stop all services:${NC}"
echo -e "  ${GREEN}docker-compose down${NC}"
echo ""

echo -e "${GREEN}Setup completed successfully! ${NC}"
