#!/bin/bash

# Protei SecuritySuite - Quick Setup Script

set -e

echo "=========================================="
echo "  Protei SecuritySuite - Quick Setup"
echo "=========================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Change to repository directory
cd /home/user/Protei_Security

echo -e "${YELLOW}Step 1: Generating SSL Certificates...${NC}"
mkdir -p certs

if [ ! -f "certs/server.crt" ]; then
    openssl req -x509 -newkey rsa:4096 -keyout certs/server.key -out certs/server.crt \
      -days 365 -nodes -subj "/CN=protei-manager/O=Protei Security/C=US"
    echo -e "${GREEN}✓ Server certificate generated${NC}"
else
    echo -e "${GREEN}✓ Server certificate already exists${NC}"
fi

if [ ! -f "certs/client.crt" ]; then
    openssl req -x509 -newkey rsa:4096 -keyout certs/client.key -out certs/client.crt \
      -days 365 -nodes -subj "/CN=protei-agent/O=Protei Security/C=US"
    echo -e "${GREEN}✓ Client certificate generated${NC}"
else
    echo -e "${GREEN}✓ Client certificate already exists${NC}"
fi

if [ ! -f "certs/ca.crt" ]; then
    openssl req -x509 -newkey rsa:4096 -keyout certs/ca.key -out certs/ca.crt \
      -days 365 -nodes -subj "/CN=protei-ca/O=Protei Security/C=US"
    echo -e "${GREEN}✓ CA certificate generated${NC}"
else
    echo -e "${GREEN}✓ CA certificate already exists${NC}"
fi

chmod 600 certs/*.key
chmod 644 certs/*.crt

echo ""
echo -e "${YELLOW}Step 2: Configuring Environment...${NC}"

if [ ! -f ".env" ]; then
    cp .env.example .env

    # Generate secure passwords
    DB_PASSWORD=$(openssl rand -base64 32)
    JWT_SECRET=$(openssl rand -base64 48)
    SCANNER_API_KEY=$(openssl rand -base64 32)

    # Update .env file
    cat > .env << EOF
# Database Configuration
DB_PASSWORD=${DB_PASSWORD}
POSTGRES_DB=protei_security
POSTGRES_USER=protei

# Security
JWT_SECRET=${JWT_SECRET}
SCANNER_API_KEY=${SCANNER_API_KEY}

# Central Manager
MANAGER_HOST=0.0.0.0
MANAGER_PORT=8443

# Logging
LOG_LEVEL=info
EOF

    echo -e "${GREEN}✓ Environment configured with secure passwords${NC}"
else
    echo -e "${GREEN}✓ Environment file already exists${NC}"
fi

echo ""
echo -e "${YELLOW}Step 3: Starting Docker Containers...${NC}"

docker compose up -d --build

echo ""
echo -e "${YELLOW}Step 4: Waiting for services to be ready...${NC}"
sleep 15

echo ""
echo -e "${YELLOW}Step 5: Checking service status...${NC}"
docker compose ps

echo ""
echo -e "${GREEN}=========================================="
echo "  Setup Complete!"
echo "==========================================${NC}"
echo ""
echo "Platform Access:"
echo "  Web Interface: https://localhost"
echo "  API Endpoint:  https://localhost:8443/api/v1"
echo ""
echo "Next Steps:"
echo "  1. Create admin user (see below)"
echo "  2. Change default password"
echo "  3. Configure firewall rules"
echo ""
echo -e "${YELLOW}To create admin user, run:${NC}"
echo "  docker compose exec postgres psql -U protei -d protei_security << 'EOF'"
echo "  DO \$\$"
echo "  DECLARE"
echo "      admin_role_id UUID;"
echo "  BEGIN"
echo "      SELECT id INTO admin_role_id FROM roles WHERE name = 'admin';"
echo "      INSERT INTO users (id, username, email, password_hash, full_name, role_id, is_active)"
echo "      SELECT gen_random_uuid(), 'admin', 'admin@protei.local',"
echo "             '\$2a\$10\$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy',"
echo "             'System Administrator', admin_role_id, true"
echo "      WHERE NOT EXISTS (SELECT 1 FROM users WHERE username = 'admin');"
echo "  END \$\$;"
echo "  EOF"
echo ""
echo "Default credentials: admin / admin (CHANGE IMMEDIATELY!)"
echo ""
echo -e "${YELLOW}View logs:${NC} docker compose logs -f"
echo ""
