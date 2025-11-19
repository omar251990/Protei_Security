# Protei_SecuritySuite - Quick Start Guide

This guide will help you get Protei_SecuritySuite up and running in under 15 minutes.

## Prerequisites

Before you begin, ensure you have:

- Docker and Docker Compose installed
- At least 4GB RAM available
- 50GB free disk space
- Linux, macOS, or Windows with WSL2

## Step 1: Clone the Repository

```bash
git clone https://github.com/protei/security-suite.git
cd Protei_Security
```

## Step 2: Configure Environment

Create your environment configuration:

```bash
cp .env.example .env
```

Edit `.env` and set secure passwords:

```bash
# Generate secure passwords
openssl rand -base64 32  # Use for DB_PASSWORD
openssl rand -base64 48  # Use for JWT_SECRET
openssl rand -base64 32  # Use for SCANNER_API_KEY
```

Update `.env`:
```
DB_PASSWORD=<your_generated_db_password>
JWT_SECRET=<your_generated_jwt_secret>
SCANNER_API_KEY=<your_generated_api_key>
```

## Step 3: Generate SSL Certificates

Generate development certificates (for production, use proper CA-signed certificates):

```bash
make gen-certs
```

This creates:
- `certs/server.crt` and `certs/server.key` - Manager server certificate
- `certs/client.crt` and `certs/client.key` - Agent client certificate
- `certs/ca.crt` and `certs/ca.key` - Certificate Authority

## Step 4: Start the Platform

Build and start all services:

```bash
docker-compose up -d
```

Wait for services to be healthy (30-60 seconds):

```bash
docker-compose ps
```

You should see:
- protei-postgres (healthy)
- protei-redis (healthy)
- protei-manager (running)

## Step 5: Create Admin User

### Option A: Using the script (recommended)

```bash
docker-compose exec manager /app/protei-manager create-admin \
  --username admin \
  --email admin@protei.local \
  --password "YourSecurePassword123!"
```

### Option B: Using PostgreSQL directly

```bash
docker-compose exec postgres psql -U protei -d protei_security -c "
INSERT INTO users (username, email, password_hash, full_name, role_id, is_active)
SELECT 'admin', 'admin@protei.local',
  '\$2a\$10\$XQFvZDYvJqQvFJq9KZOxYuRH.6SZKqZWN5zVqQmzqQqzqQqzqQqzqQq',
  'Administrator',
  (SELECT id FROM roles WHERE name = 'admin'),
  true
WHERE NOT EXISTS (SELECT 1 FROM users WHERE username = 'admin');
"
```

> **Default Password**: `admin` (Change immediately after first login!)

## Step 6: Access the Web Interface

Open your browser and navigate to:

```
https://localhost:443
```

**Note**: You'll see a certificate warning because we're using self-signed certificates. This is normal for development.

**Login credentials:**
- Username: `admin`
- Password: `admin` (or the password you set)

## Step 7: Initial Configuration

### 7.1 Change Admin Password

1. Click on your profile icon (top right)
2. Select "Change Password"
3. Enter a strong password

### 7.2 Add Your First Assets

#### Manual Asset Addition:
1. Navigate to **Assets** → **Add Asset**
2. Fill in:
   - Hostname
   - IP Address
   - Asset Type (Server, Workstation, Network Device, Database)
   - OS Type
3. Click **Save**

#### Network Discovery:
1. Navigate to **Scans** → **New Scan**
2. Select scan type: **Network Discovery**
3. Enter target:
   - Single IP: `192.168.1.100`
   - IP Range: `192.168.1.1-192.168.1.254`
   - CIDR: `192.168.1.0/24`
4. Click **Start Scan**

## Step 8: Deploy Linux Agent (Optional)

On a Linux system you want to monitor:

```bash
# Download agent binary
wget https://your-protei-server:8443/downloads/protei-agent-linux

# Make it executable
chmod +x protei-agent-linux

# Create config directory
sudo mkdir -p /etc/protei/certs

# Copy certificates from manager
scp user@protei-server:/path/to/certs/client.* /etc/protei/certs/
scp user@protei-server:/path/to/certs/ca.crt /etc/protei/certs/

# Create agent configuration
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

# Install security tools
sudo apt-get update
sudo apt-get install -y clamav chkrootkit rkhunter

# Update ClamAV database
sudo freshclam

# Run agent
sudo ./protei-agent-linux --config /etc/protei/agent.conf
```

### Install as systemd service:

```bash
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

[Install]
WantedBy=multi-user.target
EOF

sudo cp protei-agent-linux /usr/local/bin/
sudo systemctl daemon-reload
sudo systemctl enable protei-agent
sudo systemctl start protei-agent
sudo systemctl status protei-agent
```

## Step 9: Run Your First Vulnerability Scan

1. Navigate to **Scans** → **New Scan**
2. Select scan type: **Vulnerability Scan**
3. Configure:
   - **Name**: "Weekly Network Scan"
   - **Target**: Select asset group or IP range
   - **Ports**: Use default or customize
   - **Schedule**: Set to recurring (e.g., weekly)
4. Click **Start Scan**

Monitor progress in **Scans** → **Active Scans**

## Step 10: View Results

### Dashboard
Navigate to **Dashboard** to see:
- Total assets
- Vulnerability count by severity
- Recent security events
- Agent status

### Vulnerabilities
Navigate to **Vulnerabilities** to:
- Filter by severity (Critical, High, Medium, Low)
- View affected assets
- See CVE details and remediation steps
- Assign to team members

### Generate Reports
1. Navigate to **Reports** → **Generate Report**
2. Select report type:
   - Executive Summary
   - Technical Details
   - Compliance Report (PCI-DSS, ISO 27001)
3. Choose date range and assets
4. Generate PDF or Excel

## Common Tasks

### Update CVE Database

CVE database updates automatically daily at 2 AM. To trigger manual update:

```bash
docker-compose exec manager /app/protei-manager cve-sync
```

### View Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f manager
docker-compose logs -f postgres
```

### Backup Database

```bash
# Create backup
docker-compose exec postgres pg_dump -U protei protei_security > backup_$(date +%Y%m%d).sql

# Restore backup
docker-compose exec -T postgres psql -U protei protei_security < backup_20250119.sql
```

### Stop Platform

```bash
docker-compose down
```

### Stop and remove all data (⚠️ WARNING: This deletes everything!)

```bash
docker-compose down -v
```

## Troubleshooting

### Manager won't start

Check logs:
```bash
docker-compose logs manager
```

Common issues:
- Database not ready: Wait for postgres to be healthy
- Certificate issues: Regenerate with `make gen-certs`
- Port conflict: Change MANAGER_PORT in .env

### Agent can't connect

1. Check manager is accessible:
```bash
curl -k https://YOUR_MANAGER_IP:8443/health
```

2. Verify certificates are correct
3. Check firewall allows port 8443
4. Verify API key in agent config

### Scan not finding assets

1. Verify network connectivity from scanner container:
```bash
docker-compose exec scanner ping 192.168.1.1
```

2. Check firewall rules allow scanning
3. Verify target IP range is correct

### Database connection errors

```bash
# Check postgres is running
docker-compose ps postgres

# Check credentials
docker-compose exec postgres psql -U protei -d protei_security -c "SELECT 1;"
```

## Next Steps

1. **Configure Integrations**:
   - Set up SIEM integration (webhook)
   - Configure email notifications
   - Add IP reputation API keys

2. **Customize Scanning**:
   - Create custom scan profiles
   - Define exclusion lists
   - Set scan schedules

3. **Set Up Compliance**:
   - Enable compliance profiles (PCI-DSS, ISO 27001)
   - Schedule compliance scans
   - Generate compliance reports

4. **Scale Up**:
   - Deploy additional scanner nodes
   - Set up database replication
   - Configure load balancing

5. **Security Hardening**:
   - Replace self-signed certificates with CA-signed
   - Enable MFA for users
   - Configure strict firewall rules
   - Set up audit log monitoring

## Getting Help

- **Documentation**: See `/docs` directory
- **API Docs**: https://localhost:8443/swagger/
- **Logs**: `docker-compose logs -f`
- **Issues**: Report at GitHub Issues

---

**🎉 Congratulations!** You now have a fully functional enterprise security platform running.
