package models

import (
	"database/sql/driver"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// JSONB is a custom type for PostgreSQL JSONB
type JSONB map[string]interface{}

func (j JSONB) Value() (driver.Value, error) {
	return json.Marshal(j)
}

func (j *JSONB) Scan(value interface{}) error {
	if value == nil {
		*j = make(JSONB)
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return nil
	}
	return json.Unmarshal(bytes, j)
}

// StringArray for PostgreSQL array types
type StringArray []string

func (a StringArray) Value() (driver.Value, error) {
	if len(a) == 0 {
		return "{}", nil
	}
	return "{" + join(a, ",") + "}", nil
}

func join(arr []string, sep string) string {
	result := ""
	for i, s := range arr {
		if i > 0 {
			result += sep
		}
		result += s
	}
	return result
}

// Base model with common fields
type BaseModel struct {
	ID        uuid.UUID      `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`
}

// BeforeCreate hook to generate UUID
func (base *BaseModel) BeforeCreate(tx *gorm.DB) error {
	if base.ID == uuid.Nil {
		base.ID = uuid.New()
	}
	return nil
}

// User represents a system user
type User struct {
	BaseModel
	Username             string     `gorm:"uniqueIndex;size:100;not null" json:"username"`
	Email                string     `gorm:"uniqueIndex;size:255;not null" json:"email"`
	PasswordHash         string     `gorm:"size:255;not null" json:"-"`
	FullName             string     `gorm:"size:255" json:"full_name"`
	RoleID               uuid.UUID  `gorm:"type:uuid" json:"role_id"`
	Role                 *Role      `gorm:"foreignKey:RoleID" json:"role,omitempty"`
	IsActive             bool       `gorm:"default:true" json:"is_active"`
	LastLoginAt          *time.Time `json:"last_login_at,omitempty"`
	FailedLoginAttempts  int        `gorm:"default:0" json:"-"`
	LockedUntil          *time.Time `json:"-"`
}

// Role represents a user role with permissions
type Role struct {
	BaseModel
	Name        string `gorm:"uniqueIndex;size:100;not null" json:"name"`
	Description string `json:"description"`
	Permissions JSONB  `gorm:"type:jsonb;default:'[]'" json:"permissions"`
}

// Asset represents a discovered or managed asset
type Asset struct {
	BaseModel
	AssetType        string     `gorm:"size:50;not null;index" json:"asset_type"` // server, workstation, network_device, database
	Hostname         string     `gorm:"size:255;index" json:"hostname"`
	IPAddress        string     `gorm:"type:inet;not null;index" json:"ip_address"`
	MACAddress       string     `gorm:"type:macaddr" json:"mac_address,omitempty"`
	OSType           string     `gorm:"size:100;index" json:"os_type"` // linux, windows, cisco_ios, etc.
	OSName           string     `gorm:"size:255" json:"os_name"`
	OSVersion        string     `gorm:"size:100" json:"os_version"`
	OSArchitecture   string     `gorm:"size:50" json:"os_architecture"`
	FQDN             string     `gorm:"size:255" json:"fqdn,omitempty"`

	// Network information
	VlanID           *int       `json:"vlan_id,omitempty"`
	Subnet           string     `gorm:"type:cidr" json:"subnet,omitempty"`
	Gateway          string     `gorm:"type:inet" json:"gateway,omitempty"`

	// Asset status
	Status           string     `gorm:"size:50;default:'active';index" json:"status"` // active, inactive, quarantined, decommissioned
	IsCritical       bool       `gorm:"default:false" json:"is_critical"`
	BusinessOwner    string     `gorm:"size:255" json:"business_owner,omitempty"`
	TechnicalOwner   string     `gorm:"size:255" json:"technical_owner,omitempty"`
	Location         string     `gorm:"size:255" json:"location,omitempty"`

	// Discovery
	DiscoveryMethod  string     `gorm:"size:50" json:"discovery_method"` // network_scan, agent, manual, import
	FirstSeen        time.Time  `gorm:"default:now()" json:"first_seen"`
	LastSeen         time.Time  `gorm:"default:now()" json:"last_seen"`

	// Agent information
	HasAgent         bool       `gorm:"default:false" json:"has_agent"`
	AgentID          *uuid.UUID `gorm:"type:uuid" json:"agent_id,omitempty"`
	Agent            *Agent     `gorm:"foreignKey:AgentID" json:"agent,omitempty"`
	AgentVersion     string     `gorm:"size:50" json:"agent_version,omitempty"`

	// Metadata
	Tags             JSONB      `gorm:"type:jsonb;default:'[]'" json:"tags"`
	CustomFields     JSONB      `gorm:"type:jsonb;default:'{}'" json:"custom_fields"`
	Notes            string     `json:"notes,omitempty"`
}

// Agent represents an endpoint agent
type Agent struct {
	BaseModel
	AgentType             string     `gorm:"size:50;not null;index" json:"agent_type"` // linux, windows
	Hostname              string     `gorm:"size:255;not null;index" json:"hostname"`
	IPAddress             string     `gorm:"type:inet;not null;index" json:"ip_address"`
	Version               string     `gorm:"size:50;not null" json:"version"`
	BuildDate             *time.Time `gorm:"type:date" json:"build_date,omitempty"`

	// Authentication
	ClientCertFingerprint string     `gorm:"size:255;uniqueIndex;not null" json:"client_cert_fingerprint"`
	APIKeyHash            string     `gorm:"size:255;not null" json:"-"`

	// Status
	Status                string     `gorm:"size:50;default:'pending';index" json:"status"` // pending, active, inactive, disabled
	LastHeartbeat         *time.Time `json:"last_heartbeat,omitempty"`
	LastInventoryUpdate   *time.Time `json:"last_inventory_update,omitempty"`

	// Configuration
	ScanSchedule          JSONB      `gorm:"type:jsonb" json:"scan_schedule,omitempty"`
	EnabledModules        JSONB      `gorm:"type:jsonb;default:'[\"inventory\",\"malware\",\"rootkit\",\"auth_log\"]'" json:"enabled_modules"`

	// Metadata
	Tags                  JSONB      `gorm:"type:jsonb;default:'[]'" json:"tags"`
	Notes                 string     `json:"notes,omitempty"`
	RegisteredAt          time.Time  `gorm:"default:now()" json:"registered_at"`
}

// ScanJob represents a scan job definition
type ScanJob struct {
	BaseModel
	Name             string     `gorm:"size:255;not null" json:"name"`
	Description      string     `json:"description,omitempty"`

	// Scan type
	ScanType         string     `gorm:"size:50;not null;index" json:"scan_type"` // network_scan, vulnerability_scan, db_security_scan, compliance_scan

	// Targets
	TargetType       string     `gorm:"size:50;not null" json:"target_type"` // asset, asset_group, ip_range, vlan
	TargetIDs        JSONB      `gorm:"type:jsonb" json:"target_ids,omitempty"`
	TargetRanges     StringArray `gorm:"type:text[]" json:"target_ranges,omitempty"`

	// Scan configuration
	ScanConfig       JSONB      `gorm:"type:jsonb;not null" json:"scan_config"`

	// Scheduling
	ScheduleType     string     `gorm:"size:50;default:'manual'" json:"schedule_type"` // manual, once, recurring
	ScheduleCron     string     `gorm:"size:100" json:"schedule_cron,omitempty"`
	ScheduleNextRun  *time.Time `gorm:"index" json:"schedule_next_run,omitempty"`

	// Status
	IsEnabled        bool       `gorm:"default:true;index" json:"is_enabled"`
	LastRunID        *uuid.UUID `gorm:"type:uuid" json:"last_run_id,omitempty"`
	LastRunAt        *time.Time `json:"last_run_at,omitempty"`

	// Notifications
	NotificationConfig JSONB    `gorm:"type:jsonb" json:"notification_config,omitempty"`

	CreatedBy        uuid.UUID  `gorm:"type:uuid" json:"created_by"`
	Creator          *User      `gorm:"foreignKey:CreatedBy" json:"creator,omitempty"`
}

// ScanExecution represents a scan execution instance
type ScanExecution struct {
	BaseModel
	JobID                uuid.UUID  `gorm:"type:uuid;not null;index" json:"job_id"`
	Job                  *ScanJob   `gorm:"foreignKey:JobID" json:"job,omitempty"`

	// Execution details
	Status               string     `gorm:"size:50;default:'pending';index" json:"status"` // pending, running, completed, failed, cancelled
	Progress             int        `gorm:"default:0" json:"progress"` // 0-100

	// Results summary
	AssetsScanned        int        `gorm:"default:0" json:"assets_scanned"`
	PortsScanned         int        `gorm:"default:0" json:"ports_scanned"`
	ServicesDetected     int        `gorm:"default:0" json:"services_detected"`
	VulnerabilitiesFound int        `gorm:"default:0" json:"vulnerabilities_found"`
	CriticalVulns        int        `gorm:"default:0" json:"critical_vulns"`
	HighVulns            int        `gorm:"default:0" json:"high_vulns"`
	MediumVulns          int        `gorm:"default:0" json:"medium_vulns"`
	LowVulns             int        `gorm:"default:0" json:"low_vulns"`

	// Timing
	StartedAt            *time.Time `gorm:"index" json:"started_at,omitempty"`
	CompletedAt          *time.Time `json:"completed_at,omitempty"`
	DurationSeconds      *int       `json:"duration_seconds,omitempty"`

	// Error handling
	ErrorMessage         string     `json:"error_message,omitempty"`
	Warnings             StringArray `gorm:"type:text[]" json:"warnings,omitempty"`

	// Results
	ResultSummary        JSONB      `gorm:"type:jsonb" json:"result_summary,omitempty"`
}

// Vulnerability represents a detected vulnerability
type Vulnerability struct {
	BaseModel
	AssetID              uuid.UUID  `gorm:"type:uuid;not null;index" json:"asset_id"`
	Asset                *Asset     `gorm:"foreignKey:AssetID" json:"asset,omitempty"`
	CVEID                string     `gorm:"size:50;index" json:"cve_id,omitempty"`
	ScanExecutionID      uuid.UUID  `gorm:"type:uuid;index" json:"scan_execution_id"`

	// Vulnerability details
	Title                string     `gorm:"size:500;not null" json:"title"`
	Description          string     `json:"description,omitempty"`
	Severity             string     `gorm:"size:20;not null;index" json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW, INFO
	CVSSScore            *float32   `gorm:"type:decimal(3,1);index" json:"cvss_score,omitempty"`

	// Affected component
	Port                 *int       `json:"port,omitempty"`
	Protocol             string     `gorm:"size:10" json:"protocol,omitempty"`
	ServiceName          string     `gorm:"size:100" json:"service_name,omitempty"`
	ServiceVersion       string     `gorm:"size:255" json:"service_version,omitempty"`
	AffectedPackage      string     `gorm:"size:255" json:"affected_package,omitempty"`
	InstalledVersion     string     `gorm:"size:100" json:"installed_version,omitempty"`
	FixedVersion         string     `gorm:"size:100" json:"fixed_version,omitempty"`

	// Risk assessment
	RiskScore            *int       `json:"risk_score,omitempty"` // 0-100
	Exploitability       string     `gorm:"size:20" json:"exploitability,omitempty"`
	Impact               string     `gorm:"size:20" json:"impact,omitempty"`

	// Status
	Status               string     `gorm:"size:50;default:'open';index" json:"status"` // open, acknowledged, mitigated, false_positive, accepted, closed
	RemediationPriority  string     `gorm:"size:20" json:"remediation_priority,omitempty"` // urgent, high, medium, low

	// Remediation
	Solution             string     `json:"solution,omitempty"`
	RemediationSteps     string     `json:"remediation_steps,omitempty"`
	Workaround           string     `json:"workaround,omitempty"`

	// Verification
	Verified             bool       `gorm:"default:false" json:"verified"`
	VerifiedAt           *time.Time `json:"verified_at,omitempty"`
	VerifiedBy           *uuid.UUID `gorm:"type:uuid" json:"verified_by,omitempty"`

	// False positive handling
	IsFalsePositive      bool       `gorm:"default:false" json:"is_false_positive"`
	FalsePositiveReason  string     `json:"false_positive_reason,omitempty"`

	// Tracking
	AssignedTo           *uuid.UUID `gorm:"type:uuid" json:"assigned_to,omitempty"`
	DueDate              *time.Time `gorm:"type:date" json:"due_date,omitempty"`
	TicketID             string     `gorm:"size:100" json:"ticket_id,omitempty"`

	// Dates
	FirstDetected        time.Time  `gorm:"default:now();index" json:"first_detected"`
	LastDetected         time.Time  `gorm:"default:now()" json:"last_detected"`
	ResolvedAt           *time.Time `json:"resolved_at,omitempty"`

	// Metadata
	Tags                 JSONB      `gorm:"type:jsonb;default:'[]'" json:"tags"`
	Notes                string     `json:"notes,omitempty"`
}

// Event represents a security event or alert
type Event struct {
	BaseModel
	EventType      string     `gorm:"size:100;not null;index" json:"event_type"` // malware_detected, rootkit_found, brute_force, etc.
	Severity       string     `gorm:"size:20;not null;index" json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW, INFO

	// Source
	SourceType     string     `gorm:"size:50;index" json:"source_type,omitempty"` // agent, scanner, netmon, db_scanner
	SourceID       *uuid.UUID `gorm:"type:uuid" json:"source_id,omitempty"`
	AssetID        *uuid.UUID `gorm:"type:uuid;index" json:"asset_id,omitempty"`
	Asset          *Asset     `gorm:"foreignKey:AssetID" json:"asset,omitempty"`

	// Event details
	Title          string     `gorm:"size:500;not null" json:"title"`
	Description    string     `json:"description,omitempty"`

	// Context
	IPAddress      string     `gorm:"type:inet" json:"ip_address,omitempty"`
	Username       string     `gorm:"size:255" json:"username,omitempty"`
	ProcessName    string     `gorm:"size:255" json:"process_name,omitempty"`
	FilePath       string     `json:"file_path,omitempty"`
	CommandLine    string     `json:"command_line,omitempty"`

	// Detection
	Indicators     JSONB      `gorm:"type:jsonb" json:"indicators,omitempty"` // IOCs
	RawData        JSONB      `gorm:"type:jsonb" json:"raw_data,omitempty"`

	// Response
	Status         string     `gorm:"size:50;default:'new';index" json:"status"` // new, investigating, resolved, false_positive
	AssignedTo     *uuid.UUID `gorm:"type:uuid" json:"assigned_to,omitempty"`
	ResolutionNotes string    `json:"resolution_notes,omitempty"`
	ResolvedAt     *time.Time `json:"resolved_at,omitempty"`

	OccurredAt     time.Time  `gorm:"default:now();index" json:"occurred_at"`
}

// AgentScanResult represents agent-specific scan results
type AgentScanResult struct {
	BaseModel
	AgentID          uuid.UUID  `gorm:"type:uuid;not null;index" json:"agent_id"`
	Agent            *Agent     `gorm:"foreignKey:AgentID" json:"agent,omitempty"`
	AssetID          uuid.UUID  `gorm:"type:uuid;not null;index" json:"asset_id"`
	Asset            *Asset     `gorm:"foreignKey:AssetID" json:"asset,omitempty"`

	ScanModule       string     `gorm:"size:50;not null;index" json:"scan_module"` // malware, rootkit, crontab, users, etc.

	// Status
	Status           string     `gorm:"size:50;default:'clean';index" json:"status"` // clean, threats_found, suspicious, error

	// Findings
	Findings         JSONB      `gorm:"type:jsonb" json:"findings,omitempty"`
	ThreatCount      int        `gorm:"default:0" json:"threat_count"`
	SuspiciousCount  int        `gorm:"default:0" json:"suspicious_count"`

	// Module-specific fields
	MalwareSignatures    StringArray `gorm:"type:text[]" json:"malware_signatures,omitempty"`
	InfectedFiles        StringArray `gorm:"type:text[]" json:"infected_files,omitempty"`
	RootkitIndicators    StringArray `gorm:"type:text[]" json:"rootkit_indicators,omitempty"`
	SuspiciousUsers      StringArray `gorm:"type:text[]" json:"suspicious_users,omitempty"`
	SuspiciousCronJobs   StringArray `gorm:"type:text[]" json:"suspicious_cron_jobs,omitempty"`
	ListeningPorts       JSONB      `gorm:"type:jsonb" json:"listening_ports,omitempty"`
	UnexpectedPorts      []int      `gorm:"type:integer[]" json:"unexpected_ports,omitempty"`
	ModifiedFiles        StringArray `gorm:"type:text[]" json:"modified_files,omitempty"`
	NewFiles             StringArray `gorm:"type:text[]" json:"new_files,omitempty"`
	FailedLogins         int        `gorm:"default:0" json:"failed_logins"`
	UnknownLogins        JSONB      `gorm:"type:jsonb" json:"unknown_logins,omitempty"`
	SuspiciousIPs        StringArray `gorm:"type:text[]" json:"suspicious_ips,omitempty"`

	// Raw output
	RawOutput        string     `json:"raw_output,omitempty"`

	ScanDurationSeconds int     `json:"scan_duration_seconds,omitempty"`
	ScannedAt        time.Time  `gorm:"default:now();index" json:"scanned_at"`
}
