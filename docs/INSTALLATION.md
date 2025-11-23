# Protei_SecuritySuite - Installation Guide

## Prerequisites Installation

### Install Docker and Docker Compose on Ubuntu/Debian

```bash
# Update package index
sudo apt update

# Install prerequisites
sudo apt install -y ca-certificates curl gnupg lsb-release

# Add Docker's official GPG key
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

# Set up Docker repository
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker Engine
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Verify installation
sudo docker --version
sudo docker compose version

# Add your user to docker group (optional - allows running docker without sudo)
sudo usermod -aG docker $USER
newgrp docker

# Test Docker installation
docker run hello-world
```

### Install Docker on CentOS/RHEL

```bash
# Install prerequisites
sudo yum install -y yum-utils
sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo

# Install Docker Engine
sudo yum install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Start Docker
sudo systemctl start docker
sudo systemctl enable docker

# Verify installation
sudo docker --version
sudo docker compose version
```

## Protei_SecuritySuite Installation

### Step 1: Generate SSL Certificates

```bash
cd /usr/protei/Protei_Security

# Create certificates directory
mkdir -p certs

# Generate Server Certificate (Central Manager)
openssl req -x509 -newkey rsa:4096 -keyout certs/server.key -out certs/server.crt \
  -days 365 -nodes -subj "/CN=protei-manager/O=Protei Security/C=US"

# Generate Client Certificate (Agents)
openssl req -x509 -newkey rsa:4096 -keyout certs/client.key -out certs/client.crt \
  -days 365 -nodes -subj "/CN=protei-agent/O=Protei Security/C=US"

# Generate CA Certificate
openssl req -x509 -newkey rsa:4096 -keyout certs/ca.key -out certs/ca.crt \
  -days 365 -nodes -subj "/CN=protei-ca/O=Protei Security/C=US"

# Set proper permissions
chmod 600 certs/*.key
chmod 644 certs/*.crt
```

### Step 2: Configure Environment

```bash
# Copy example environment file
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

echo "✓ Environment configured"
echo "✓ Credentials saved to .env"
```

### Step 3: Start the Platform

```bash
# Build and start all services
docker compose up -d

# Wait for services to be healthy (30-60 seconds)
echo "Waiting for services to start..."
sleep 30

# Check service status
docker compose ps

# Expected output:
# NAME                IMAGE                              STATUS
# protei-manager      protei_security-manager           Up (healthy)
# protei-postgres     postgres:15                        Up (healthy)
# protei-redis        redis:7-alpine                     Up (healthy)
# protei-scanner      protei_security-scanner           Up
# protei-web          protei_security-web               Up
```

### Step 4: View Logs

```bash
# View all logs
docker compose logs -f

# View specific service logs
docker compose logs -f manager
docker compose logs -f postgres

# Press Ctrl+C to exit log viewing
```

### Step 5: Access the Platform

Open your browser and navigate to:

```
https://localhost
```

or

```
https://YOUR_SERVER_IP
```

You'll see the Protei Security Suite web interface with:
- Platform status dashboard
- API endpoint information
- Links to API documentation

### Step 6: Create Admin User

There are two options to create the admin user:

#### Option A: Using SQL (Quickest)

```bash
# Create admin user with default password 'admin'
docker compose exec postgres psql -U protei -d protei_security << 'EOF'
-- Get admin role ID
DO $$
DECLARE
    admin_role_id UUID;
BEGIN
    SELECT id INTO admin_role_id FROM roles WHERE name = 'admin';

    -- Insert admin user if not exists
    INSERT INTO users (id, username, email, password_hash, full_name, role_id, is_active)
    SELECT
        gen_random_uuid(),
        'admin',
        'admin@protei.local',
        '$2a$10$XQFvZDYvJqQvFJq9KZOxYeRH.6SZKqZWN5zVqQmzqQqzqQqzqQqzq',
        'System Administrator',
        admin_role_id,
        true
    WHERE NOT EXISTS (SELECT 1 FROM users WHERE username = 'admin');
END $$;
EOF

echo "✓ Admin user created"
echo "Username: admin"
echo "Password: admin (CHANGE THIS IMMEDIATELY!)"
```

#### Option B: Using Go Script

Create a script to generate a user with a secure password:

```bash
cat > /tmp/create_admin.go << 'SCRIPT'
package main

import (
    "fmt"
    "golang.org/x/crypto/bcrypt"
)

func main() {
    password := "YourSecurePassword123!"
    hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    fmt.Println(string(hash))
}
SCRIPT

# Generate password hash
go run /tmp/create_admin.go
```

### Step 7: Test API Access

```bash
# Login to get JWT token
curl -k -X POST https://localhost:8443/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "admin"
  }' | jq .

# Save the token from response
export TOKEN="<your_token_here>"

# Test authenticated endpoint
curl -k https://localhost:8443/api/v1/dashboard/stats \
  -H "Authorization: Bearer $TOKEN" | jq .
```

## Post-Installation Configuration

### 1. Change Admin Password

```bash
# Via API
curl -k -X PUT https://localhost:8443/api/v1/users/me/password \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "current_password": "admin",
    "new_password": "YourNewSecurePassword123!"
  }'
```

### 2. Configure Firewall

```bash
# Allow HTTPS access
sudo ufw allow 443/tcp
sudo ufw allow 8443/tcp

# If using firewalld (CentOS/RHEL)
sudo firewall-cmd --permanent --add-port=443/tcp
sudo firewall-cmd --permanent --add-port=8443/tcp
sudo firewall-cmd --reload
```

### 3. Set Up Automatic Startup

```bash
# Docker Compose services will auto-start on boot by default
# To disable:
# docker compose down --remove-orphans
```

### 4. Configure Log Rotation

Create `/etc/logrotate.d/protei-security`:

```bash
sudo cat > /etc/logrotate.d/protei-security << 'EOF'
/var/lib/docker/containers/*/*.log {
    rotate 7
    daily
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
EOF
```

## Installing Linux Agent on Remote Systems

### On the target Linux system:

```bash
# 1. Download agent binary from manager
wget --no-check-certificate https://YOUR_MANAGER_IP:8443/downloads/protei-agent-linux

# Or copy from manager server
scp user@manager:/usr/protei/Protei_Security/bin/protei-agent-linux .

# 2. Make executable
chmod +x protei-agent-linux

# 3. Create directories
sudo mkdir -p /etc/protei/certs
sudo mkdir -p /var/log/protei

# 4. Copy certificates
scp user@manager:/usr/protei/Protei_Security/certs/client.* /tmp/
scp user@manager:/usr/protei/Protei_Security/certs/ca.crt /tmp/
sudo mv /tmp/client.* /etc/protei/certs/
sudo mv /tmp/ca.crt /etc/protei/certs/
sudo chmod 600 /etc/protei/certs/*.key

# 5. Get API key from .env on manager
# On manager: cat .env | grep SCANNER_API_KEY

# 6. Create agent configuration
sudo cat > /etc/protei/agent.conf << 'EOF'
{
  "manager_url": "https://YOUR_MANAGER_IP:8443",
  "api_key": "YOUR_SCANNER_API_KEY",
  "client_cert": "/etc/protei/certs/client.crt",
  "client_key": "/etc/protei/certs/client.key",
  "ca_cert": "/etc/protei/certs/ca.crt",
  "heartbeat_interval": 60,
  "scan_schedule": "0 2 * * *"
}
EOF

# 7. Install security tools
sudo apt update
sudo apt install -y clamav clamav-daemon chkrootkit rkhunter

# Update ClamAV database
sudo freshclam

# 8. Create systemd service
sudo cat > /etc/systemd/system/protei-agent.service << 'EOF'
[Unit]
Description=Protei Security Agent
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/protei-agent-linux --config /etc/protei/agent.conf
Restart=always
RestartSec=10
StandardOutput=append:/var/log/protei/agent.log
StandardError=append:/var/log/protei/agent-error.log

[Install]
WantedBy=multi-user.target
EOF

# 9. Install and start service
sudo cp protei-agent-linux /usr/local/bin/
sudo systemctl daemon-reload
sudo systemctl enable protei-agent
sudo systemctl start protei-agent

# 10. Check status
sudo systemctl status protei-agent
sudo tail -f /var/log/protei/agent.log
```

## Troubleshooting

### Services won't start

```bash
# Check Docker is running
sudo systemctl status docker

# Check for port conflicts
sudo netstat -tulpn | grep -E ':443|:8443|:5432'

# View detailed logs
docker compose logs --tail=100 manager

# Restart services
docker compose restart
```

### Database connection issues

```bash
# Check PostgreSQL is healthy
docker compose exec postgres pg_isready -U protei

# Test connection
docker compose exec postgres psql -U protei -d protei_security -c "SELECT version();"

# Check logs
docker compose logs postgres
```

### Certificate errors

```bash
# Regenerate certificates
rm -rf certs/*
make gen-certs

# Restart services
docker compose down
docker compose up -d
```

### Out of disk space

```bash
# Clean up Docker
docker system prune -a --volumes

# Check disk usage
df -h
docker system df
```

### Manager API not responding

```bash
# Check if container is running
docker compose ps manager

# Check container logs
docker compose logs manager --tail=50

# Restart manager
docker compose restart manager

# Check if port is accessible
curl -k https://localhost:8443/health
```

## Updating Protei_SecuritySuite

```bash
cd /usr/protei/Protei_Security

# Pull latest changes
git pull origin main

# Rebuild containers
docker compose down
docker compose build --no-cache
docker compose up -d

# Check status
docker compose ps
```

## Backup and Restore

### Backup

```bash
# Backup database
docker compose exec postgres pg_dump -U protei protei_security | gzip > backup_$(date +%Y%m%d_%H%M%S).sql.gz

# Backup configuration
tar czf config_backup_$(date +%Y%m%d).tar.gz configs/ certs/ .env
```

### Restore

```bash
# Restore database
gunzip < backup_20250119_120000.sql.gz | docker compose exec -T postgres psql -U protei protei_security

# Restore configuration
tar xzf config_backup_20250119.tar.gz
```

## Uninstallation

```bash
# Stop and remove containers
docker compose down

# Remove volumes (⚠️ WARNING: This deletes all data!)
docker compose down -v

# Remove images
docker compose down --rmi all

# Remove project directory
cd /usr/protei
sudo rm -rf Protei_Security
```

---

For additional help, see:
- [QUICKSTART.md](../QUICKSTART.md) - Quick deployment guide
- [README.md](../README.md) - Full documentation
- [ARCHITECTURE.md](../ARCHITECTURE.md) - System architecture
