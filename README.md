# Protei_SecuritySuite

**Enterprise-Grade On-Premise Security Platform**

Protei_SecuritySuite is a comprehensive security platform that provides vulnerability management, endpoint security, database security, and network monitoring capabilities similar to Nessus Professional, OpenVAS/Greenbone, and Qualys VM.

## 🚀 Features

### Core Capabilities

#### 1. **Asset Discovery & Network Scanning**
- Comprehensive network discovery across LANs, VLANs, and subnets
- OS detection and fingerprinting
- Port scanning (TCP/UDP) with configurable ranges
- Service version detection and banner grabbing
- SSL/TLS certificate analysis
- Detection of weak protocols (Telnet, FTP, SMBv1, old SSL/TLS versions)
- Network device and infrastructure discovery

#### 2. **Vulnerability Management**
- CVE database synchronization from NVD and vendor feeds
- Automated vulnerability correlation with detected services
- CVSS v2/v3 scoring and risk assessment
- EPSS (Exploit Prediction Scoring System) integration
- Exploit availability tracking
- False positive management
- Risk-based vulnerability prioritization
- Compliance mapping (PCI-DSS, ISO 27001, NIST, HIPAA)

#### 3. **Linux Endpoint Security Agent**
- **Malware Detection**: ClamAV integration with automatic updates
- **Rootkit Detection**: chkrootkit and rkhunter scanning
- **Suspicious Activity Monitoring**:
  - Crontab analysis for malicious scheduled tasks
  - User account auditing (/etc/passwd, /etc/shadow)
  - File integrity monitoring (/usr/bin, /tmp, /var/tmp)
  - World-writable file detection
- **Network Monitoring**: Listening ports analysis (ss -tulnp equivalent)
- **Auth Log Analysis**:
  - Failed login attempts detection
  - Brute-force attack identification
  - Unknown user login attempts
  - Suspicious IP tracking
- **System Inventory**: OS, packages, services, users

#### 4. **Windows Endpoint Security Agent**
- **Windows Defender Integration**:
  - Trigger offline scans
  - Query threat detection history
  - Automatic definition updates
- **Third-Party AV Support**: Malwarebytes, Sophos, ESET integration
- **Task Scheduler Analysis**: Detection of malicious scheduled tasks
- **Startup Items Inspection**:
  - Registry startup keys monitoring
  - Startup folder analysis
  - Suspicious pattern detection
- **Event Viewer Analysis**:
  - Failed logon attempts (Event ID 4625)
  - RDP logon tracking (Event ID 4624, LogonType 10)
  - PowerShell Script Block Logging (Event ID 4104)
  - Suspicious process creation (Event ID 4688)
  - Malicious PowerShell command detection

#### 5. **Database Security Module**
- **Supported Databases**: PostgreSQL, MySQL, MSSQL, MongoDB, Oracle
- **Security Assessments**:
  - User enumeration and privilege auditing
  - Weak password detection
  - Internet exposure detection (0.0.0.0 bindings)
  - SQL injection attempt detection via log analysis
  - Encryption status verification (TLS, at-rest encryption)
  - Configuration hardening recommendations
  - Backup verification
- **Compliance Checks**: PCI-DSS, HIPAA database requirements

#### 6. **Network Monitoring & IDS Integration**
- **Log Analysis**:
  - Firewall and router log ingestion (syslog, file-based)
  - Suspicious outbound connection detection
  - Brute-force attack detection (SSH, RDP, FTP)
- **Threat Intelligence**:
  - IP reputation integration (AbuseIPDB, Spamhaus, AlienVault OTX)
  - Geo-blocking policy engine
  - DGA (Domain Generation Algorithm) detection
- **IDS/IPS Integration**: Suricata and Snort alert processing
- **Traffic Anomaly Detection**: Port scanning, volumetric attacks

#### 7. **Web Management Console**
- **Dashboards**:
  - Real-time security overview
  - Vulnerability statistics by severity, asset, CVE
  - Agent health monitoring
  - Recent security events
- **Asset Management**: Group assets, assign owners, tag for organization
- **Scan Configuration**: Schedule recurring scans, configure targets
- **Alert Management**: Prioritize, assign, and track security findings
- **Report Generation**: PDF/Excel reports with custom templates

#### 8. **REST API**
- Complete programmatic access to all features
- JWT-based authentication
- Webhook support for SIEM/ticketing system integration
- OpenAPI/Swagger documentation

## 🏗️ Architecture

### Components

```
┌─────────────────────────────────────────────────────────────────┐
│                     Web Frontend (React)                         │
│                    Management Console                            │
└────────────────────────┬────────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────────┐
│                   Central Manager (Go)                           │
│  - REST API          - Job Scheduling    - Report Engine        │
│  - Authentication    - Vulnerability Correlation                │
└─────┬─────────┬──────────┬──────────┬──────────────────────────┘
      │         │          │          │
      ▼         ▼          ▼          ▼
┌──────────┐ ┌────────┐ ┌────────┐ ┌──────────┐
│ Network  │ │  CVE   │ │   DB   │ │ Network  │
│ Scanner  │ │  Sync  │ │Scanner │ │ Monitor  │
└──────────┘ └────────┘ └────────┘ └──────────┘
      │
      ▼
┌──────────────────────────────────┐
│      Target Network              │
│                                  │
│  ┌──────┐ ┌──────┐ ┌──────┐    │
│  │Linux │ │Windows│ │ DB   │    │
│  │Agent │ │Agent  │ │Server│    │
│  └──────┘ └──────┘ └──────┘    │
└──────────────────────────────────┘
```

### Technology Stack

**Backend:**
- Go 1.21+ (High performance, native concurrency)
- Gin (HTTP framework)
- GORM (ORM)
- PostgreSQL 15+ (Primary database)
- Redis (Caching and session management)

**Frontend:**
- React 18+ with TypeScript
- Material-UI or Ant Design
- Redux Toolkit (State management)
- Recharts (Data visualization)

**Infrastructure:**
- Docker & Docker Compose
- PostgreSQL for data persistence
- Optional: ClickHouse or Elasticsearch for log storage

## 📦 Installation

### Prerequisites

- Docker and Docker Compose
- 4GB RAM minimum (8GB+ recommended)
- 50GB disk space
- Linux or Windows Server OS

### Quick Start with Docker

1. **Clone the repository:**
```bash
git clone https://github.com/protei/security-suite.git
cd security-suite
```

2. **Generate certificates:**
```bash
make gen-certs
```

3. **Configure environment:**
```bash
cp .env.example .env
# Edit .env and set DB_PASSWORD and JWT_SECRET
```

4. **Start the platform:**
```bash
docker-compose up -d
```

5. **Create admin user:**
```bash
make create-admin
```

6. **Access the web interface:**
```
https://localhost:443
```

### Manual Installation

#### Build from Source

```bash
# Install dependencies
make install-deps

# Build all components
make build

# Build specific components
make build-manager        # Central Manager
make build-scanner        # Network Scanner
make build-agent-linux    # Linux Agent
make build-agent-windows  # Windows Agent
```

#### Run Components

**Central Manager:**
```bash
./bin/protei-manager --config configs/manager.yaml
```

**Linux Agent:**
```bash
sudo ./bin/protei-agent-linux --config /etc/protei/agent.conf
```

**Windows Agent:**
```powershell
.\bin\protei-agent-windows.exe -config "C:\ProgramData\Protei\agent.conf"
```

## 🔧 Configuration

### Central Manager Configuration

Edit `configs/manager.yaml`:

```yaml
server:
  host: "0.0.0.0"
  port: 8443
  tls_enabled: true
  tls_cert_file: "/etc/protei/certs/server.crt"
  tls_key_file: "/etc/protei/certs/server.key"

database:
  host: "localhost"
  port: 5432
  user: "protei"
  password: "CHANGE_ME"
  dbname: "protei_security"

security:
  jwt_secret: "CHANGE_ME"
  jwt_expiration_hours: 24
  max_login_attempts: 5

scanner:
  default_timeout: 300
  max_concurrent_scans: 5
  default_ports: ["1-1024", "3306", "5432", "8080"]
```

### Agent Configuration

**Linux Agent** (`/etc/protei/agent.conf`):
```json
{
  "manager_url": "https://protei-manager:8443",
  "api_key": "YOUR_API_KEY",
  "client_cert": "/etc/protei/certs/client.crt",
  "client_key": "/etc/protei/certs/client.key",
  "ca_cert": "/etc/protei/certs/ca.crt",
  "heartbeat_interval": 60,
  "scan_schedule": "0 2 * * *"
}
```

**Windows Agent** (`C:\ProgramData\Protei\agent.conf`):
```json
{
  "manager_url": "https://protei-manager:8443",
  "api_key": "YOUR_API_KEY",
  "client_cert": "C:\\ProgramData\\Protei\\certs\\client.crt",
  "client_key": "C:\\ProgramData\\Protei\\certs\\client.key",
  "ca_cert": "C:\\ProgramData\\Protei\\certs\\ca.crt",
  "heartbeat_interval": 60,
  "scan_schedule": "0 2 * * *"
}
```

## 📊 Usage

### Web Interface

1. **Login**: Navigate to `https://your-server:443` and login with admin credentials

2. **Dashboard**: View overview of security posture
   - Total assets and vulnerabilities
   - Critical/High severity findings
   - Active agents
   - Recent security events

3. **Asset Management**:
   - View discovered assets
   - Create asset groups
   - Assign business/technical owners
   - Tag assets for organization

4. **Scanning**:
   - Create network scan jobs
   - Schedule recurring scans
   - Configure scan targets (IP ranges, VLANs, asset groups)
   - View scan results in real-time

5. **Vulnerability Management**:
   - Filter vulnerabilities by severity, status, asset
   - Assign vulnerabilities to team members
   - Mark as false positive or accepted risk
   - Track remediation progress

6. **Reports**:
   - Generate executive summary reports
   - Technical detail reports
   - Compliance reports (PCI-DSS, ISO 27001)
   - Export to PDF or Excel

### API Usage

**Authentication:**
```bash
curl -X POST https://localhost:8443/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"your_password"}'
```

**Get Assets:**
```bash
curl https://localhost:8443/api/v1/assets \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

**Get Vulnerabilities:**
```bash
curl https://localhost:8443/api/v1/vulnerabilities?severity=CRITICAL \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

**API Documentation**: Available at `https://localhost:8443/swagger/index.html`

## 🔐 Security Features

- **mTLS Authentication**: Agents authenticate using client certificates
- **JWT Tokens**: Stateless authentication for web/API access
- **RBAC**: Role-based access control (Admin, Analyst, Auditor, Operator)
- **Audit Logging**: Complete audit trail of all actions
- **Encryption**:
  - TLS 1.3 for all communications
  - PostgreSQL pgcrypto for sensitive data at rest
- **Account Protection**:
  - Failed login attempt tracking
  - Automatic account lockout
  - Password complexity requirements

## 📈 Scalability

### Deployment Sizes

**Small Environment (< 500 assets):**
- All-in-One deployment
- Single server with Docker Compose
- 4 CPU cores, 8GB RAM, 100GB disk

**Medium Environment (500-5000 assets):**
- Distributed deployment
- Separate manager, database, and scanner nodes
- Load-balanced web frontend
- 8+ CPU cores, 16GB+ RAM across nodes

**Large Environment (5000+ assets):**
- High Availability deployment
- Clustered managers (active-active)
- Database cluster with replicas
- Multiple dedicated scanner nodes
- Distributed log storage (ClickHouse/Elasticsearch)
- 16+ CPU cores, 32GB+ RAM across cluster

## 🛠️ Development

### Project Structure

```
Protei_Security/
├── cmd/                    # Application entry points
│   ├── manager/           # Central Manager
│   ├── scanner/           # Network Scanner
│   ├── agent-linux/       # Linux Agent
│   ├── agent-windows/     # Windows Agent
│   ├── db-scanner/        # Database Scanner
│   ├── netmon/            # Network Monitor
│   └── cve-sync/          # CVE Synchronizer
├── pkg/                    # Shared libraries
│   ├── models/            # Data models
│   ├── database/          # Database layer
│   ├── api/               # API handlers
│   ├── scanner/           # Scanning logic
│   ├── agent/             # Agent logic
│   ├── auth/              # Authentication
│   ├── config/            # Configuration
│   └── logger/            # Logging
├── internal/               # Internal packages
│   ├── middleware/        # HTTP middleware
│   └── utils/             # Utilities
├── web/                    # React frontend
│   ├── src/
│   └── public/
├── configs/                # Configuration files
├── docker/                 # Dockerfiles
├── migrations/             # Database migrations
├── scripts/                # Helper scripts
└── docs/                   # Documentation
```

### Running Tests

```bash
make test
```

### Code Formatting

```bash
make fmt
```

### Linting

```bash
make lint
```

### Building

```bash
# Build all components
make build

# Build specific component
make build-manager
make build-agent-linux
```

## 📝 License

Copyright (c) 2025 Protei Security Suite

Licensed under the Apache License, Version 2.0

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines before submitting pull requests.

## 📧 Support

- Documentation: [docs/](./docs/)
- Issues: [GitHub Issues](https://github.com/protei/security-suite/issues)
- Email: support@protei-security.com

## 🎯 Roadmap

- [ ] Container security scanning (Docker, Kubernetes)
- [ ] Cloud asset discovery (AWS, Azure, GCP)
- [ ] Machine learning for anomaly detection
- [ ] Advanced SOAR capabilities
- [ ] Mobile app for iOS/Android
- [ ] Additional compliance frameworks (SOC 2, GDPR)
- [ ] Automated penetration testing modules
- [ ] Integration with popular ticketing systems (Jira, ServiceNow)

## 📖 Documentation

- [Architecture Guide](./ARCHITECTURE.md)
- [Database Schema](./DATABASE_SCHEMA.md)
- [API Documentation](./docs/api/)
- [Agent Installation Guide](./docs/agents/)
- [Deployment Guide](./docs/deployment/)
- [Security Best Practices](./docs/security/)

---

**Built with ❤️ for the security community**
