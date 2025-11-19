# Protei_SecuritySuite - System Architecture

## Overview

Protei_SecuritySuite is an enterprise-grade on-premise security platform providing comprehensive vulnerability management, endpoint security, database security, and network monitoring capabilities.

## System Components

### 1. Central Manager (Go)
**Service**: `protei-manager`
- **Purpose**: Orchestrates all operations, provides REST API, manages jobs and schedules
- **Port**: 8443 (HTTPS)
- **Features**:
  - Asset inventory management
  - Scan job scheduling and orchestration
  - Vulnerability correlation and risk scoring
  - User authentication and RBAC
  - Report generation (PDF/Excel)
  - REST API for integrations
  - WebSocket for real-time updates

### 2. Network Scanner (Go)
**Service**: `protei-scanner`
- **Purpose**: Active network scanning and service detection
- **Features**:
  - Network discovery (ARP, ICMP, TCP/UDP)
  - Port scanning (1-65535)
  - Service version detection
  - OS fingerprinting
  - SSL/TLS certificate analysis
  - Weak protocol detection (Telnet, FTP, SMBv1, SSLv3, TLS 1.0/1.1)
  - Misconfiguration detection
  - VLAN traversal support

### 3. Vulnerability Engine (Go)
**Service**: `protei-vuln-engine`
- **Purpose**: CVE correlation and vulnerability assessment
- **Features**:
  - CVE database synchronization (NVD, vendor feeds)
  - CPE matching against detected services
  - CVSS scoring and risk calculation
  - Exploit availability checking
  - Custom vulnerability rules
  - False positive management

### 4. Linux Agent (Go)
**Service**: `protei-agent-linux`
- **Deployment**: Installed on monitored Linux endpoints
- **Communication**: HTTPS/mTLS to central manager
- **Features**:
  - System inventory (OS, packages, services)
  - Malware scanning (ClamAV integration)
  - Rootkit detection (chkrootkit, rkhunter)
  - Suspicious crontab analysis
  - User account auditing (/etc/passwd, /etc/shadow)
  - File integrity monitoring (/usr/bin, /tmp, /var/tmp)
  - Network listening ports (ss -tulnp)
  - Auth log parsing (/var/log/auth.log, /var/log/secure)
  - Failed login detection
  - Sudo command auditing

### 5. Windows Agent (Go + PowerShell)
**Service**: `protei-agent-windows`
- **Deployment**: Installed on monitored Windows endpoints
- **Communication**: HTTPS/mTLS to central manager
- **Features**:
  - System inventory (OS, patches, software)
  - Microsoft Defender integration
    - Trigger offline scans
    - Query threat detection history
  - Third-party AV integration (Malwarebytes, Sophos, ESET)
  - Task Scheduler analysis
  - Startup items inspection (Registry + folders)
  - Event Viewer log parsing:
    - Security Event ID 4625 (failed logons)
    - Security Event ID 4624 (successful logons - RDP detection)
    - PowerShell Script Block Logging (Event ID 4104)
    - Process creation events (Event ID 4688)
  - Suspicious executable detection
  - Registry key monitoring

### 6. Database Security Module (Go)
**Service**: `protei-db-scanner`
- **Purpose**: Database security assessment
- **Supported DBs**: PostgreSQL, MySQL, MSSQL, MongoDB, Oracle
- **Features**:
  - Database discovery
  - User enumeration and privilege auditing
  - Weak password detection
  - Internet exposure detection (0.0.0.0 bindings)
  - SQL injection attempt detection (log analysis)
  - Configuration hardening recommendations
  - Encryption status (TLS, at-rest)
  - Backup verification
  - Compliance checking (PCI-DSS, HIPAA)

### 7. Network Monitoring & Log Analysis (Go)
**Service**: `protei-netmon`
- **Purpose**: Network traffic analysis and threat detection
- **Features**:
  - Firewall/Router log ingestion (syslog, file-based)
  - Suspicious outbound connection detection
  - Brute-force attack detection (SSH, RDP, FTP)
  - IP reputation integration (AbuseIPDB, Spamhaus, AlienVault OTX)
  - Geo-blocking policy engine
  - IDS/IPS integration (Suricata/Snort)
  - DGA domain detection
  - Port scanning detection
  - Traffic anomaly detection

### 8. Web Frontend (React + TypeScript)
**Service**: `protei-web`
- **Port**: 443 (served via nginx)
- **Features**:
  - Asset management dashboard
  - Vulnerability overview (by severity, asset, CVE)
  - Scan configuration and scheduling
  - Real-time scan progress
  - Alert management
  - Report generation interface
  - User and role management
  - System configuration
  - Charts and visualizations (Chart.js/Recharts)

### 9. Report Engine (Go)
**Service**: Part of `protei-manager`
- **Features**:
  - PDF report generation (go-pdf)
  - Excel export (excelize)
  - Custom report templates
  - Scheduled report delivery (email)
  - Executive summary reports
  - Technical detail reports
  - Compliance reports (PCI-DSS, ISO 27001, NIST)

### 10. CVE Database Updater (Go)
**Service**: `protei-cve-sync`
- **Purpose**: Keep vulnerability database current
- **Features**:
  - NVD CVE feed synchronization
  - Vendor-specific feeds (Red Hat, Ubuntu, Microsoft)
  - Exploit-DB integration
  - EPSS (Exploit Prediction Scoring System) integration
  - Automated daily updates

## System Architecture Diagram

```
                                    ┌─────────────────────────────────┐
                                    │     Web Browser (HTTPS)         │
                                    └────────────────┬────────────────┘
                                                     │
                                    ┌────────────────▼────────────────┐
                                    │   Nginx Reverse Proxy           │
                                    │   - SSL Termination             │
                                    │   - Static File Serving         │
                                    └────────────────┬────────────────┘
                                                     │
                        ┌────────────────────────────┼────────────────────────────┐
                        │                            │                            │
               ┌────────▼─────────┐      ┌──────────▼──────────┐      ┌─────────▼────────┐
               │  React Frontend  │      │  Central Manager    │      │   REST API       │
               │  (TypeScript)    │      │  (Go - protei-mgr)  │      │   Endpoints      │
               └──────────────────┘      └──────────┬──────────┘      └──────────────────┘
                                                    │
                                    ┌───────────────┼───────────────┐
                                    │       PostgreSQL DB           │
                                    │  - Assets                     │
                                    │  - Scans & Results            │
                                    │  - Vulnerabilities            │
                                    │  - Events & Alerts            │
                                    │  - Users & Config             │
                                    └───────────────┬───────────────┘
                                                    │
        ┌───────────────┬───────────────┬──────────┴──────────┬──────────────┬────────────────┐
        │               │               │                     │              │                │
┌───────▼──────┐ ┌──────▼─────┐ ┌──────▼──────┐     ┌────────▼──────┐ ┌────▼─────┐  ┌──────▼──────┐
│  Network     │ │ Vuln Engine│ │ DB Scanner  │     │  NetMon       │ │ CVE Sync │  │ Log Storage │
│  Scanner     │ │            │ │             │     │  & IDS        │ │          │  │ ClickHouse/ │
│              │ │            │ │             │     │               │ │          │  │ Elastic     │
└──────┬───────┘ └────────────┘ └─────────────┘     └───────────────┘ └──────────┘  └─────────────┘
       │
       │ Scans Network
       │
       ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│                              Target Network                                       │
│                                                                                   │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐          │
│  │ Linux    │  │ Windows  │  │ Servers  │  │ Network  │  │ Database │          │
│  │ Endpoint │  │ Endpoint │  │          │  │ Devices  │  │ Servers  │          │
│  │          │  │          │  │          │  │          │  │          │          │
│  │ Agent ▲  │  │ Agent ▲  │  │          │  │          │  │          │          │
│  └───────┼──┘  └───────┼──┘  └──────────┘  └──────────┘  └──────────┘          │
│          │              │                                                         │
│          └──────────────┴───────────── mTLS/HTTPS ──────────────────────────┐   │
└──────────────────────────────────────────────────────────────────────────────┼───┘
                                                                                │
                                                         ┌──────────────────────▼────┐
                                                         │  Agent API Endpoint       │
                                                         │  (Central Manager)        │
                                                         └───────────────────────────┘
```

## Communication Protocols

### Agent → Manager
- **Protocol**: HTTPS with mutual TLS (mTLS)
- **Authentication**: Client certificates + API keys
- **Port**: 8444
- **Endpoints**:
  - `POST /api/v1/agents/heartbeat` - Agent check-in
  - `POST /api/v1/agents/inventory` - System inventory
  - `POST /api/v1/agents/scan-results` - Security scan results
  - `GET /api/v1/agents/jobs` - Retrieve pending jobs
  - `PUT /api/v1/agents/jobs/{id}/status` - Update job status

### Manager → Database
- **Protocol**: PostgreSQL native (encrypted)
- **Connection Pool**: 50 max connections
- **Read Replicas**: Supported for scaling

### Scanner → Targets
- **Protocols**: TCP, UDP, ICMP, SNMP, HTTP/HTTPS
- **Rate Limiting**: Configurable packets/sec
- **Timeouts**: Configurable per scan type

### External Integrations
- **CVE Feeds**: HTTPS REST APIs
- **IP Reputation**: HTTPS REST APIs
- **SIEM Export**: Syslog (TCP/UDP), REST API
- **Ticketing**: REST API webhooks

## Database Schema

### Tables Overview
1. **assets** - Discovered and managed assets
2. **asset_groups** - Logical grouping of assets
3. **scan_jobs** - Scheduled and on-demand scans
4. **scan_results** - Detailed scan output
5. **vulnerabilities** - Detected vulnerabilities
6. **cve_database** - CVE definitions and metadata
7. **events** - Security events and alerts
8. **agents** - Registered endpoint agents
9. **users** - System users
10. **roles** - RBAC roles
11. **compliance_profiles** - Compliance check templates
12. **reports** - Generated reports
13. **configurations** - System settings

## Security Features

### Authentication & Authorization
- **User Auth**: bcrypt password hashing, JWT tokens
- **Agent Auth**: mTLS with certificate validation
- **RBAC**: Role-based access control
  - Admin
  - Security Analyst
  - Auditor (read-only)
  - Scanner Operator

### Data Protection
- **Encryption at Rest**: PostgreSQL pgcrypto for sensitive data
- **Encryption in Transit**: TLS 1.3 for all communications
- **Certificate Management**: Automatic cert rotation
- **Secrets Management**: Environment variables + vault integration

### Audit Logging
- All user actions logged
- All scan activities logged
- All agent communications logged
- Tamper-proof audit trail

## Scalability Design

### Horizontal Scaling
- **Scanners**: Multiple scanner instances with job queue
- **Agents**: Unlimited agents supported
- **Database**: Read replicas, connection pooling
- **Frontend**: Load-balanced nginx instances

### Performance Optimization
- **Caching**: Redis for session, scan results
- **Async Processing**: Job queues (RabbitMQ/NATS)
- **Batch Operations**: Bulk inserts for scan results
- **Indexing**: Optimized DB indexes

## Deployment Options

### 1. All-in-One (Small Environment)
- Single server running all components
- Docker Compose deployment
- Suitable for: < 500 assets

### 2. Distributed (Medium Environment)
- Manager + DB on dedicated server
- Separate scanner nodes
- Load-balanced web frontend
- Suitable for: 500-5000 assets

### 3. High Availability (Large Environment)
- Clustered managers (active-active)
- Database cluster (primary + replicas)
- Multiple scanner nodes
- Distributed log storage
- Suitable for: 5000+ assets

## Technology Stack

### Backend
- **Language**: Go 1.21+
- **Framework**: Gin (HTTP), GORM (ORM)
- **Database**: PostgreSQL 15+
- **Message Queue**: NATS/RabbitMQ
- **Cache**: Redis 7+
- **Log Storage**: ClickHouse or Elasticsearch

### Frontend
- **Framework**: React 18+
- **Language**: TypeScript 5+
- **UI Library**: Material-UI or Ant Design
- **State Management**: Redux Toolkit
- **Charts**: Recharts or Chart.js
- **Build**: Vite

### DevOps
- **Containers**: Docker
- **Orchestration**: Docker Compose / Kubernetes
- **CI/CD**: GitHub Actions
- **Monitoring**: Prometheus + Grafana
- **Logging**: ELK Stack or Loki

## Module Dependencies

```
protei-manager (central hub)
├── protei-scanner (invoked for network scans)
├── protei-vuln-engine (invoked for CVE correlation)
├── protei-db-scanner (invoked for database scans)
├── protei-netmon (continuous monitoring)
├── protei-cve-sync (scheduled updates)
└── protei-web (user interface)

Agents (independent, push to manager)
├── protei-agent-linux
└── protei-agent-windows
```

## API Design Principles

1. **RESTful**: Standard HTTP methods (GET, POST, PUT, DELETE)
2. **Versioned**: `/api/v1/` prefix for future compatibility
3. **JSON**: All requests/responses in JSON
4. **Paginated**: Large result sets paginated
5. **Filtered**: Support for filtering, sorting, searching
6. **Rate Limited**: Prevent abuse
7. **Documented**: OpenAPI/Swagger documentation

## Next Steps

1. Implement database schema (PostgreSQL migrations)
2. Build central manager with core API endpoints
3. Build Linux agent with basic inventory
4. Build network scanner module
5. Implement vulnerability correlation engine
6. Build frontend dashboard
7. Add reporting capabilities
8. Implement Windows agent
9. Add database security module
10. Implement network monitoring
