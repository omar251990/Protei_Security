# Protei_SecuritySuite - Database Schema

## Database: PostgreSQL 15+

## Schema Design Principles

1. **Normalization**: Properly normalized to 3NF
2. **Indexing**: Strategic indexes for query performance
3. **Partitioning**: Time-series tables partitioned by date
4. **Constraints**: Foreign keys, unique constraints, check constraints
5. **Audit Trails**: Created/updated timestamps on all tables
6. **Soft Deletes**: Deleted_at for important records

---

## Core Tables

### 1. users
User accounts for the web interface

```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(255),
    role_id UUID REFERENCES roles(id),
    is_active BOOLEAN DEFAULT true,
    last_login_at TIMESTAMP,
    failed_login_attempts INT DEFAULT 0,
    locked_until TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    deleted_at TIMESTAMP
);

CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_role_id ON users(role_id);
```

### 2. roles
RBAC roles

```sql
CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    permissions JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Insert default roles
INSERT INTO roles (name, description, permissions) VALUES
('admin', 'Full system access', '["*"]'),
('security_analyst', 'Vulnerability management and scanning',
 '["assets.read", "assets.write", "scans.read", "scans.write", "vulnerabilities.read", "reports.read"]'),
('auditor', 'Read-only access for compliance',
 '["assets.read", "scans.read", "vulnerabilities.read", "reports.read", "events.read"]'),
('scanner_operator', 'Scan execution only',
 '["scans.read", "scans.write", "assets.read"]');
```

### 3. assets
Discovered and managed assets

```sql
CREATE TABLE assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_type VARCHAR(50) NOT NULL, -- 'server', 'workstation', 'network_device', 'database', 'container'
    hostname VARCHAR(255),
    ip_address INET NOT NULL,
    mac_address MACADDR,
    os_type VARCHAR(100), -- 'linux', 'windows', 'cisco_ios', 'unknown'
    os_name VARCHAR(255),
    os_version VARCHAR(100),
    os_architecture VARCHAR(50),
    fqdn VARCHAR(255),

    -- Network information
    vlan_id INT,
    subnet CIDR,
    gateway INET,

    -- Asset status
    status VARCHAR(50) DEFAULT 'active', -- 'active', 'inactive', 'quarantined', 'decommissioned'
    is_critical BOOLEAN DEFAULT false,
    business_owner VARCHAR(255),
    technical_owner VARCHAR(255),
    location VARCHAR(255),

    -- Discovery
    discovery_method VARCHAR(50), -- 'network_scan', 'agent', 'manual', 'import'
    first_seen TIMESTAMP DEFAULT NOW(),
    last_seen TIMESTAMP DEFAULT NOW(),

    -- Agent information (if agent installed)
    has_agent BOOLEAN DEFAULT false,
    agent_id UUID REFERENCES agents(id),
    agent_version VARCHAR(50),

    -- Metadata
    tags JSONB DEFAULT '[]',
    custom_fields JSONB DEFAULT '{}',
    notes TEXT,

    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    deleted_at TIMESTAMP
);

CREATE INDEX idx_assets_ip_address ON assets(ip_address);
CREATE INDEX idx_assets_hostname ON assets(hostname);
CREATE INDEX idx_assets_asset_type ON assets(asset_type);
CREATE INDEX idx_assets_os_type ON assets(os_type);
CREATE INDEX idx_assets_status ON assets(status);
CREATE INDEX idx_assets_vlan_id ON assets(vlan_id);
CREATE INDEX idx_assets_agent_id ON assets(agent_id);
CREATE INDEX idx_assets_tags ON assets USING gin(tags);
```

### 4. asset_groups
Logical grouping of assets

```sql
CREATE TABLE asset_groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    group_type VARCHAR(50) DEFAULT 'manual', -- 'manual', 'dynamic', 'vlan', 'location'

    -- Dynamic group criteria (for auto-population)
    criteria JSONB, -- e.g., {"os_type": "linux", "vlan_id": 10}

    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE asset_group_members (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id UUID REFERENCES asset_groups(id) ON DELETE CASCADE,
    asset_id UUID REFERENCES assets(id) ON DELETE CASCADE,
    added_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(group_id, asset_id)
);

CREATE INDEX idx_asset_group_members_group_id ON asset_group_members(group_id);
CREATE INDEX idx_asset_group_members_asset_id ON asset_group_members(asset_id);
```

### 5. agents
Registered endpoint agents

```sql
CREATE TABLE agents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_type VARCHAR(50) NOT NULL, -- 'linux', 'windows'
    hostname VARCHAR(255) NOT NULL,
    ip_address INET NOT NULL,

    -- Agent software info
    version VARCHAR(50) NOT NULL,
    build_date DATE,

    -- Authentication
    client_cert_fingerprint VARCHAR(255) UNIQUE NOT NULL,
    api_key_hash VARCHAR(255) NOT NULL,

    -- Status
    status VARCHAR(50) DEFAULT 'pending', -- 'pending', 'active', 'inactive', 'disabled'
    last_heartbeat TIMESTAMP,
    last_inventory_update TIMESTAMP,

    -- Configuration
    scan_schedule JSONB, -- cron-like schedule
    enabled_modules JSONB DEFAULT '["inventory", "malware", "rootkit", "auth_log"]',

    -- Metadata
    tags JSONB DEFAULT '[]',
    notes TEXT,

    registered_at TIMESTAMP DEFAULT NOW(),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    deleted_at TIMESTAMP
);

CREATE INDEX idx_agents_hostname ON agents(hostname);
CREATE INDEX idx_agents_ip_address ON agents(ip_address);
CREATE INDEX idx_agents_status ON agents(status);
CREATE INDEX idx_agents_agent_type ON agents(agent_type);
```

### 6. scan_jobs
Scan job definitions and schedules

```sql
CREATE TABLE scan_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,

    -- Scan type
    scan_type VARCHAR(50) NOT NULL, -- 'network_scan', 'vulnerability_scan', 'db_security_scan', 'compliance_scan'

    -- Targets
    target_type VARCHAR(50) NOT NULL, -- 'asset', 'asset_group', 'ip_range', 'vlan'
    target_ids JSONB, -- array of asset/group IDs
    target_ranges TEXT[], -- array of IP ranges: ['192.168.1.0/24', '10.0.0.1-10.0.0.50']

    -- Scan configuration
    scan_config JSONB NOT NULL, -- port ranges, timing, credentials, etc.

    -- Scheduling
    schedule_type VARCHAR(50) DEFAULT 'manual', -- 'manual', 'once', 'recurring'
    schedule_cron VARCHAR(100), -- cron expression for recurring
    schedule_next_run TIMESTAMP,

    -- Status
    is_enabled BOOLEAN DEFAULT true,
    last_run_id UUID REFERENCES scan_executions(id),
    last_run_at TIMESTAMP,

    -- Notifications
    notification_config JSONB, -- email, webhooks on completion/issues

    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    deleted_at TIMESTAMP
);

CREATE INDEX idx_scan_jobs_scan_type ON scan_jobs(scan_type);
CREATE INDEX idx_scan_jobs_schedule_next_run ON scan_jobs(schedule_next_run);
CREATE INDEX idx_scan_jobs_is_enabled ON scan_jobs(is_enabled);
```

### 7. scan_executions
Individual scan execution instances

```sql
CREATE TABLE scan_executions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id UUID REFERENCES scan_jobs(id) ON DELETE CASCADE,

    -- Execution details
    status VARCHAR(50) DEFAULT 'pending', -- 'pending', 'running', 'completed', 'failed', 'cancelled'
    progress INT DEFAULT 0, -- 0-100

    -- Results summary
    assets_scanned INT DEFAULT 0,
    ports_scanned INT DEFAULT 0,
    services_detected INT DEFAULT 0,
    vulnerabilities_found INT DEFAULT 0,
    critical_vulns INT DEFAULT 0,
    high_vulns INT DEFAULT 0,
    medium_vulns INT DEFAULT 0,
    low_vulns INT DEFAULT 0,

    -- Timing
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    duration_seconds INT,

    -- Error handling
    error_message TEXT,
    warnings TEXT[],

    -- Results
    result_summary JSONB,

    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_scan_executions_job_id ON scan_executions(job_id);
CREATE INDEX idx_scan_executions_status ON scan_executions(status);
CREATE INDEX idx_scan_executions_started_at ON scan_executions(started_at);
```

### 8. scan_results
Detailed scan results (partitioned by month)

```sql
CREATE TABLE scan_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    execution_id UUID REFERENCES scan_executions(id) ON DELETE CASCADE,
    asset_id UUID REFERENCES assets(id),

    -- What was scanned
    scan_type VARCHAR(50) NOT NULL,
    target VARCHAR(255) NOT NULL, -- IP, hostname, or identifier

    -- Port/Service details
    port INT,
    protocol VARCHAR(10), -- 'tcp', 'udp'
    service_name VARCHAR(100),
    service_version VARCHAR(255),
    service_product VARCHAR(255),
    service_cpe VARCHAR(500), -- Common Platform Enumeration

    -- TLS/SSL information
    ssl_enabled BOOLEAN,
    ssl_version VARCHAR(50),
    ssl_cipher VARCHAR(255),
    ssl_cert_expiry TIMESTAMP,
    ssl_cert_subject TEXT,

    -- Banner/Response
    banner TEXT,
    http_headers JSONB,

    -- Detection metadata
    confidence VARCHAR(20), -- 'high', 'medium', 'low'
    detection_method VARCHAR(100),

    -- Raw output
    raw_output TEXT,

    scanned_at TIMESTAMP DEFAULT NOW(),
    created_at TIMESTAMP DEFAULT NOW()
) PARTITION BY RANGE (created_at);

-- Create partitions for each month (example for 2025)
CREATE TABLE scan_results_2025_01 PARTITION OF scan_results
    FOR VALUES FROM ('2025-01-01') TO ('2025-02-01');
-- ... additional partitions created automatically

CREATE INDEX idx_scan_results_execution_id ON scan_results(execution_id);
CREATE INDEX idx_scan_results_asset_id ON scan_results(asset_id);
CREATE INDEX idx_scan_results_port ON scan_results(port);
CREATE INDEX idx_scan_results_service_name ON scan_results(service_name);
```

### 9. cve_database
CVE definitions (updated daily)

```sql
CREATE TABLE cve_database (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id VARCHAR(50) UNIQUE NOT NULL, -- e.g., 'CVE-2024-1234'

    -- CVSS scores
    cvss_v3_score DECIMAL(3,1),
    cvss_v3_vector VARCHAR(255),
    cvss_v2_score DECIMAL(3,1),
    cvss_v2_vector VARCHAR(255),

    -- Severity
    severity VARCHAR(20), -- 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE'

    -- Description
    description TEXT,
    references TEXT[], -- array of URLs

    -- Affected products (CPE)
    cpe_matches JSONB, -- array of CPE strings with version ranges

    -- Exploit information
    exploit_available BOOLEAN DEFAULT false,
    exploit_maturity VARCHAR(50), -- 'proof_of_concept', 'functional', 'high'
    exploit_references TEXT[],

    -- EPSS (Exploit Prediction Scoring System)
    epss_score DECIMAL(5,4),
    epss_percentile DECIMAL(5,4),

    -- CWE (Common Weakness Enumeration)
    cwe_ids VARCHAR(50)[],

    -- Dates
    published_date DATE,
    modified_date DATE,

    -- Vendor advisories
    vendor_advisories JSONB,

    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_cve_database_cve_id ON cve_database(cve_id);
CREATE INDEX idx_cve_database_severity ON cve_database(severity);
CREATE INDEX idx_cve_database_cvss_v3_score ON cve_database(cvss_v3_score);
CREATE INDEX idx_cve_database_published_date ON cve_database(published_date);
CREATE INDEX idx_cve_database_cpe_matches ON cve_database USING gin(cpe_matches);
```

### 10. vulnerabilities
Detected vulnerabilities on assets

```sql
CREATE TABLE vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id UUID REFERENCES assets(id),
    cve_id VARCHAR(50) REFERENCES cve_database(cve_id),
    scan_execution_id UUID REFERENCES scan_executions(id),

    -- Vulnerability details
    title VARCHAR(500) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL, -- 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'
    cvss_score DECIMAL(3,1),

    -- Affected component
    port INT,
    protocol VARCHAR(10),
    service_name VARCHAR(100),
    service_version VARCHAR(255),
    affected_package VARCHAR(255),
    installed_version VARCHAR(100),
    fixed_version VARCHAR(100),

    -- Risk assessment
    risk_score INT, -- custom risk score 0-100
    exploitability VARCHAR(20), -- 'critical', 'high', 'medium', 'low'
    impact VARCHAR(20),

    -- Status
    status VARCHAR(50) DEFAULT 'open', -- 'open', 'acknowledged', 'mitigated', 'false_positive', 'accepted', 'closed'
    remediation_priority VARCHAR(20), -- 'urgent', 'high', 'medium', 'low'

    -- Remediation
    solution TEXT,
    remediation_steps TEXT,
    workaround TEXT,

    -- Verification
    verified BOOLEAN DEFAULT false,
    verified_at TIMESTAMP,
    verified_by UUID REFERENCES users(id),

    -- False positive handling
    is_false_positive BOOLEAN DEFAULT false,
    false_positive_reason TEXT,

    -- Tracking
    assigned_to UUID REFERENCES users(id),
    due_date DATE,
    ticket_id VARCHAR(100), -- external ticketing system ID

    -- Dates
    first_detected TIMESTAMP DEFAULT NOW(),
    last_detected TIMESTAMP DEFAULT NOW(),
    resolved_at TIMESTAMP,

    -- Metadata
    tags JSONB DEFAULT '[]',
    notes TEXT,

    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_vulnerabilities_asset_id ON vulnerabilities(asset_id);
CREATE INDEX idx_vulnerabilities_cve_id ON vulnerabilities(cve_id);
CREATE INDEX idx_vulnerabilities_severity ON vulnerabilities(severity);
CREATE INDEX idx_vulnerabilities_status ON vulnerabilities(status);
CREATE INDEX idx_vulnerabilities_cvss_score ON vulnerabilities(cvss_score);
CREATE INDEX idx_vulnerabilities_first_detected ON vulnerabilities(first_detected);
```

### 11. events
Security events and alerts (partitioned by month)

```sql
CREATE TABLE events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type VARCHAR(100) NOT NULL, -- 'malware_detected', 'rootkit_found', 'brute_force', 'suspicious_login', etc.
    severity VARCHAR(20) NOT NULL, -- 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'

    -- Source
    source_type VARCHAR(50), -- 'agent', 'scanner', 'netmon', 'db_scanner'
    source_id UUID, -- agent_id or scanner job ID
    asset_id UUID REFERENCES assets(id),

    -- Event details
    title VARCHAR(500) NOT NULL,
    description TEXT,

    -- Context
    ip_address INET,
    username VARCHAR(255),
    process_name VARCHAR(255),
    file_path TEXT,
    command_line TEXT,

    -- Detection
    indicators JSONB, -- IOCs (indicators of compromise)
    raw_data JSONB,

    -- Response
    status VARCHAR(50) DEFAULT 'new', -- 'new', 'investigating', 'resolved', 'false_positive'
    assigned_to UUID REFERENCES users(id),
    resolution_notes TEXT,
    resolved_at TIMESTAMP,

    occurred_at TIMESTAMP DEFAULT NOW(),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
) PARTITION BY RANGE (occurred_at);

-- Monthly partitions
CREATE TABLE events_2025_01 PARTITION OF events
    FOR VALUES FROM ('2025-01-01') TO ('2025-02-01');

CREATE INDEX idx_events_event_type ON events(event_type);
CREATE INDEX idx_events_severity ON events(severity);
CREATE INDEX idx_events_asset_id ON events(asset_id);
CREATE INDEX idx_events_status ON events(status);
CREATE INDEX idx_events_occurred_at ON events(occurred_at);
```

### 12. agent_scan_results
Agent-specific scan results (malware, rootkit, etc.)

```sql
CREATE TABLE agent_scan_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID REFERENCES agents(id),
    asset_id UUID REFERENCES assets(id),

    scan_module VARCHAR(50) NOT NULL, -- 'malware', 'rootkit', 'crontab', 'users', 'file_integrity', 'network_ports', 'auth_logs'

    -- Status
    status VARCHAR(50) DEFAULT 'clean', -- 'clean', 'threats_found', 'suspicious', 'error'

    -- Findings
    findings JSONB, -- detailed findings from the scan
    threat_count INT DEFAULT 0,
    suspicious_count INT DEFAULT 0,

    -- Malware-specific
    malware_signatures TEXT[],
    infected_files TEXT[],

    -- Rootkit-specific
    rootkit_indicators TEXT[],

    -- User/Crontab specific
    suspicious_users TEXT[],
    suspicious_cron_jobs TEXT[],

    -- Network ports
    listening_ports JSONB,
    unexpected_ports INT[],

    -- File integrity
    modified_files TEXT[],
    new_files TEXT[],

    -- Auth logs
    failed_logins INT DEFAULT 0,
    unknown_logins JSONB,
    suspicious_ips INET[],

    -- Raw output
    raw_output TEXT,

    scan_duration_seconds INT,
    scanned_at TIMESTAMP DEFAULT NOW(),
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_agent_scan_results_agent_id ON agent_scan_results(agent_id);
CREATE INDEX idx_agent_scan_results_asset_id ON agent_scan_results(asset_id);
CREATE INDEX idx_agent_scan_results_scan_module ON agent_scan_results(scan_module);
CREATE INDEX idx_agent_scan_results_status ON agent_scan_results(status);
CREATE INDEX idx_agent_scan_results_scanned_at ON agent_scan_results(scanned_at);
```

### 13. database_security_findings
Database security assessment results

```sql
CREATE TABLE database_security_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id UUID REFERENCES assets(id),

    -- Database info
    db_type VARCHAR(50) NOT NULL, -- 'postgresql', 'mysql', 'mssql', 'mongodb', 'oracle'
    db_version VARCHAR(100),
    db_name VARCHAR(255),

    -- Finding details
    finding_type VARCHAR(100) NOT NULL, -- 'exposed_to_internet', 'weak_password', 'unknown_user', 'sql_injection_attempt', 'missing_encryption'
    severity VARCHAR(20) NOT NULL,
    title VARCHAR(500) NOT NULL,
    description TEXT,

    -- Evidence
    evidence JSONB,

    -- Specific findings
    exposed_to_internet BOOLEAN,
    binding_address INET,
    unknown_users TEXT[],
    users_without_password TEXT[],
    privileged_users TEXT[],

    -- Encryption status
    tls_enabled BOOLEAN,
    encryption_at_rest BOOLEAN,

    -- SQL injection
    injection_attempts INT DEFAULT 0,
    injection_sources INET[],

    -- Remediation
    recommendation TEXT,

    -- Status
    status VARCHAR(50) DEFAULT 'open',
    resolved_at TIMESTAMP,

    detected_at TIMESTAMP DEFAULT NOW(),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_db_security_findings_asset_id ON database_security_findings(asset_id);
CREATE INDEX idx_db_security_findings_finding_type ON database_security_findings(finding_type);
CREATE INDEX idx_db_security_findings_severity ON database_security_findings(severity);
CREATE INDEX idx_db_security_findings_status ON database_security_findings(status);
```

### 14. network_monitoring_events
Network monitoring and IDS alerts (ClickHouse/Elasticsearch recommended for large scale)

```sql
CREATE TABLE network_monitoring_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Event type
    event_category VARCHAR(100) NOT NULL, -- 'brute_force', 'port_scan', 'suspicious_outbound', 'ids_alert', 'geo_block'

    -- Network details
    source_ip INET NOT NULL,
    source_port INT,
    source_country VARCHAR(2),
    source_asn INT,

    dest_ip INET NOT NULL,
    dest_port INT,

    protocol VARCHAR(20),

    -- IDS/IPS details
    signature_id INT,
    signature_name VARCHAR(500),
    classification VARCHAR(100),

    -- Reputation
    ip_reputation_score INT, -- 0-100, higher is worse
    is_blacklisted BOOLEAN DEFAULT false,
    blacklist_sources TEXT[],

    -- Brute force detection
    failed_attempts INT,
    attack_duration_seconds INT,

    -- Details
    severity VARCHAR(20) NOT NULL,
    description TEXT,
    raw_log TEXT,

    -- Response
    action_taken VARCHAR(50), -- 'logged', 'blocked', 'alerted'

    occurred_at TIMESTAMP DEFAULT NOW(),
    created_at TIMESTAMP DEFAULT NOW()
) PARTITION BY RANGE (occurred_at);

-- Monthly partitions
CREATE TABLE network_monitoring_events_2025_01 PARTITION OF network_monitoring_events
    FOR VALUES FROM ('2025-01-01') TO ('2025-02-01');

CREATE INDEX idx_netmon_events_source_ip ON network_monitoring_events(source_ip);
CREATE INDEX idx_netmon_events_dest_ip ON network_monitoring_events(dest_ip);
CREATE INDEX idx_netmon_events_event_category ON network_monitoring_events(event_category);
CREATE INDEX idx_netmon_events_severity ON network_monitoring_events(severity);
CREATE INDEX idx_netmon_events_occurred_at ON network_monitoring_events(occurred_at);
```

### 15. reports
Generated reports

```sql
CREATE TABLE reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    report_type VARCHAR(100) NOT NULL, -- 'vulnerability_summary', 'compliance', 'executive', 'technical_detail', 'trend_analysis'

    -- Scope
    scope_type VARCHAR(50), -- 'all_assets', 'asset_group', 'specific_assets'
    scope_ids JSONB,

    -- Time range
    start_date DATE,
    end_date DATE,

    -- Format
    format VARCHAR(20) NOT NULL, -- 'pdf', 'excel', 'json', 'html'
    file_path VARCHAR(500),
    file_size_bytes BIGINT,

    -- Content summary
    total_assets INT,
    total_vulnerabilities INT,
    critical_findings INT,
    high_findings INT,

    -- Generation
    status VARCHAR(50) DEFAULT 'pending', -- 'pending', 'generating', 'completed', 'failed'
    error_message TEXT,

    generated_by UUID REFERENCES users(id),
    generated_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP, -- auto-delete old reports

    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_reports_report_type ON reports(report_type);
CREATE INDEX idx_reports_generated_by ON reports(generated_by);
CREATE INDEX idx_reports_generated_at ON reports(generated_at);
```

### 16. configurations
System configurations and settings

```sql
CREATE TABLE configurations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    config_key VARCHAR(255) UNIQUE NOT NULL,
    config_value JSONB NOT NULL,
    description TEXT,
    is_encrypted BOOLEAN DEFAULT false,

    modified_by UUID REFERENCES users(id),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Insert default configurations
INSERT INTO configurations (config_key, config_value, description) VALUES
('scan.default_timeout', '300', 'Default scan timeout in seconds'),
('scan.max_concurrent_scans', '5', 'Maximum number of concurrent scans'),
('scan.default_ports', '["1-1024", "3306", "5432", "8080", "8443"]', 'Default port ranges to scan'),
('agent.heartbeat_interval', '60', 'Agent heartbeat interval in seconds'),
('agent.max_offline_duration', '3600', 'Mark agent offline after this many seconds'),
('cve.update_schedule', '"0 2 * * *"', 'CVE database update schedule (cron)'),
('notification.email_enabled', 'false', 'Enable email notifications'),
('notification.webhook_enabled', 'false', 'Enable webhook notifications'),
('security.password_min_length', '12', 'Minimum password length'),
('security.session_timeout', '3600', 'Session timeout in seconds'),
('security.mfa_required', 'false', 'Require MFA for all users');
```

### 17. compliance_profiles
Compliance check templates (PCI-DSS, ISO 27001, etc.)

```sql
CREATE TABLE compliance_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) UNIQUE NOT NULL,
    framework VARCHAR(100) NOT NULL, -- 'PCI-DSS', 'ISO-27001', 'NIST-800-53', 'HIPAA', 'CIS'
    version VARCHAR(50),
    description TEXT,

    -- Check definitions
    checks JSONB NOT NULL, -- array of check definitions

    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE compliance_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    profile_id UUID REFERENCES compliance_profiles(id),
    asset_id UUID REFERENCES assets(id),

    -- Results
    total_checks INT,
    passed_checks INT,
    failed_checks INT,
    skipped_checks INT,
    compliance_percentage DECIMAL(5,2),

    -- Detailed results
    check_results JSONB,

    assessed_at TIMESTAMP DEFAULT NOW(),
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_compliance_results_profile_id ON compliance_results(profile_id);
CREATE INDEX idx_compliance_results_asset_id ON compliance_results(asset_id);
```

### 18. audit_logs
Complete audit trail

```sql
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id),
    action VARCHAR(100) NOT NULL, -- 'login', 'logout', 'scan_created', 'vulnerability_modified', etc.
    resource_type VARCHAR(100),
    resource_id UUID,

    -- Details
    description TEXT,
    ip_address INET,
    user_agent TEXT,

    -- Changes
    old_values JSONB,
    new_values JSONB,

    occurred_at TIMESTAMP DEFAULT NOW()
) PARTITION BY RANGE (occurred_at);

-- Monthly partitions
CREATE TABLE audit_logs_2025_01 PARTITION OF audit_logs
    FOR VALUES FROM ('2025-01-01') TO ('2025-02-01');

CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_occurred_at ON audit_logs(occurred_at);
```

---

## Views for Common Queries

### Active Vulnerabilities by Severity
```sql
CREATE VIEW v_active_vulnerabilities_by_severity AS
SELECT
    severity,
    COUNT(*) as count,
    COUNT(DISTINCT asset_id) as affected_assets
FROM vulnerabilities
WHERE status IN ('open', 'acknowledged')
    AND deleted_at IS NULL
GROUP BY severity;
```

### Asset Security Score
```sql
CREATE VIEW v_asset_security_scores AS
SELECT
    a.id,
    a.hostname,
    a.ip_address,
    COUNT(v.id) as total_vulnerabilities,
    SUM(CASE WHEN v.severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical_count,
    SUM(CASE WHEN v.severity = 'HIGH' THEN 1 ELSE 0 END) as high_count,
    SUM(CASE WHEN v.severity = 'MEDIUM' THEN 1 ELSE 0 END) as medium_count,
    SUM(CASE WHEN v.severity = 'LOW' THEN 1 ELSE 0 END) as low_count,
    -- Simple security score: 100 - weighted vulnerabilities
    GREATEST(0, 100 - (
        SUM(CASE WHEN v.severity = 'CRITICAL' THEN 10 ELSE 0 END) +
        SUM(CASE WHEN v.severity = 'HIGH' THEN 5 ELSE 0 END) +
        SUM(CASE WHEN v.severity = 'MEDIUM' THEN 2 ELSE 0 END) +
        SUM(CASE WHEN v.severity = 'LOW' THEN 1 ELSE 0 END)
    )) as security_score
FROM assets a
LEFT JOIN vulnerabilities v ON a.id = v.asset_id
    AND v.status IN ('open', 'acknowledged')
WHERE a.deleted_at IS NULL
GROUP BY a.id, a.hostname, a.ip_address;
```

---

## Indexes Summary

All critical foreign keys and query patterns are indexed for optimal performance.

## Partitioning Strategy

Large time-series tables are partitioned by month:
- `scan_results` - by created_at
- `events` - by occurred_at
- `network_monitoring_events` - by occurred_at
- `audit_logs` - by occurred_at

Automatic partition creation can be handled by pg_partman extension.

## Backup & Retention

- **Full backups**: Daily
- **WAL archiving**: Continuous
- **Retention**:
  - Scan results: 90 days
  - Events: 180 days
  - Audit logs: 365 days (compliance requirement)
  - Vulnerabilities: Until resolved + 30 days

## Migration Files

SQL migration files will be created in `migrations/` directory using a migration tool like golang-migrate or goose.
