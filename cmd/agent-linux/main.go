package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/protei/security-suite/pkg/agent"
	"github.com/robfig/cron/v3"
)

const (
	Version = "1.0.0"
)

// Config holds agent configuration
type Config struct {
	ManagerURL       string
	APIKey           string
	ClientCert       string
	ClientKey        string
	CACert           string
	HeartbeatInterval int
	ScanSchedule     string
}

// AgentClient handles communication with the manager
type AgentClient struct {
	config     Config
	httpClient *http.Client
	agentID    string
}

func main() {
	// Parse command line flags
	configFile := flag.String("config", "/etc/protei/agent.conf", "Configuration file path")
	flag.Parse()

	log.Printf("Protei Security Suite - Linux Agent v%s\n", Version)

	// Load configuration
	config, err := loadConfig(*configFile)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Create agent client
	client, err := NewAgentClient(config)
	if err != nil {
		log.Fatalf("Failed to create agent client: %v", err)
	}

	// Register with manager if not already registered
	if err := client.Register(); err != nil {
		log.Printf("Warning: Failed to register with manager: %v", err)
	}

	// Start heartbeat
	go client.StartHeartbeat()

	// Setup scheduled scans
	if config.ScanSchedule != "" {
		client.SetupScheduledScans(config.ScanSchedule)
	}

	// Run initial inventory and security scan
	log.Println("Running initial security assessment...")
	if err := client.RunFullSecurityScan(); err != nil {
		log.Printf("Initial scan failed: %v", err)
	}

	// Keep running
	select {}
}

// NewAgentClient creates a new agent client
func NewAgentClient(config Config) (*AgentClient, error) {
	// Load client certificate
	cert, err := tls.LoadX509KeyPair(config.ClientCert, config.ClientKey)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate: %w", err)
	}

	// Load CA certificate
	caCert, err := os.ReadFile(config.CACert)
	if err != nil {
		return nil, fmt.Errorf("failed to load CA certificate: %w", err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Create TLS configuration
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}

	// Create HTTP client with TLS
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		Timeout: 30 * time.Second,
	}

	return &AgentClient{
		config:     config,
		httpClient: httpClient,
	}, nil
}

// Register registers the agent with the manager
func (c *AgentClient) Register() error {
	inventory, err := agent.CollectInventory()
	if err != nil {
		return err
	}

	registrationData := map[string]interface{}{
		"agent_type": "linux",
		"hostname":   inventory.Hostname,
		"ip_address": inventory.IPAddress,
		"version":    Version,
		"os_info": map[string]string{
			"os_name":    inventory.OSName,
			"os_version": inventory.OSVersion,
			"kernel":     inventory.Kernel,
		},
	}

	resp, err := c.sendRequest("POST", "/api/v1/agents/register", registrationData)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
		var result map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&result); err == nil {
			if agentID, ok := result["agent_id"].(string); ok {
				c.agentID = agentID
				log.Printf("Agent registered successfully with ID: %s", agentID)
			}
		}
	}

	return nil
}

// StartHeartbeat sends periodic heartbeats to the manager
func (c *AgentClient) StartHeartbeat() {
	ticker := time.NewTicker(time.Duration(c.config.HeartbeatInterval) * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if err := c.sendHeartbeat(); err != nil {
			log.Printf("Heartbeat failed: %v", err)
		}
	}
}

func (c *AgentClient) sendHeartbeat() error {
	data := map[string]interface{}{
		"timestamp": time.Now().Unix(),
		"status":    "active",
	}

	resp, err := c.sendRequest("POST", "/api/v1/agents/heartbeat", data)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		log.Println("Heartbeat sent successfully")
	}

	return nil
}

// SetupScheduledScans configures scheduled security scans
func (c *AgentClient) SetupScheduledScans(schedule string) {
	cronScheduler := cron.New()

	// Schedule full security scan
	cronScheduler.AddFunc(schedule, func() {
		log.Println("Running scheduled security scan...")
		if err := c.RunFullSecurityScan(); err != nil {
			log.Printf("Scheduled scan failed: %v", err)
		}
	})

	cronScheduler.Start()
	log.Printf("Scheduled scans configured: %s", schedule)
}

// RunFullSecurityScan performs all security checks
func (c *AgentClient) RunFullSecurityScan() error {
	log.Println("=== Starting Full Security Scan ===")

	// 1. Collect inventory
	log.Println("[1/7] Collecting system inventory...")
	inventory, err := agent.CollectInventory()
	if err != nil {
		log.Printf("Inventory collection failed: %v", err)
	} else {
		c.sendInventory(inventory)
	}

	// 2. Malware scan
	log.Println("[2/7] Running malware scan...")
	malwareScan, err := agent.RunMalwareScan([]string{"/home", "/tmp", "/var/tmp"})
	if err != nil {
		log.Printf("Malware scan failed: %v", err)
	} else {
		c.sendScanResult(malwareScan)
		if malwareScan.Status == "threats_found" {
			log.Printf("⚠️  ALERT: %d malware threats detected!", malwareScan.ThreatCount)
		}
	}

	// 3. Rootkit scan
	log.Println("[3/7] Running rootkit detection...")
	rootkitScan, err := agent.RunRootkitScan()
	if err != nil {
		log.Printf("Rootkit scan failed: %v", err)
	} else {
		c.sendScanResult(rootkitScan)
		if rootkitScan.Status == "threats_found" {
			log.Printf("⚠️  ALERT: Rootkit indicators detected!")
		}
	}

	// 4. Crontab check
	log.Println("[4/7] Checking crontab for suspicious entries...")
	crontabCheck, err := agent.CheckCrontab()
	if err != nil {
		log.Printf("Crontab check failed: %v", err)
	} else {
		c.sendScanResult(crontabCheck)
		if crontabCheck.SuspiciousCount > 0 {
			log.Printf("⚠️  WARNING: %d suspicious cron jobs found", crontabCheck.SuspiciousCount)
		}
	}

	// 5. User account audit
	log.Println("[5/7] Auditing user accounts...")
	userCheck, err := agent.CheckUsers()
	if err != nil {
		log.Printf("User check failed: %v", err)
	} else {
		c.sendScanResult(userCheck)
		if userCheck.SuspiciousCount > 0 {
			log.Printf("⚠️  WARNING: %d suspicious user accounts found", userCheck.SuspiciousCount)
		}
	}

	// 6. File integrity check
	log.Println("[6/7] Checking file integrity...")
	fileCheck, err := agent.CheckFileIntegrity([]string{"/usr/bin", "/tmp", "/var/tmp"})
	if err != nil {
		log.Printf("File integrity check failed: %v", err)
	} else {
		c.sendScanResult(fileCheck)
		if fileCheck.SuspiciousCount > 0 {
			log.Printf("⚠️  WARNING: %d suspicious files detected", fileCheck.SuspiciousCount)
		}
	}

	// 7. Auth log analysis
	log.Println("[7/7] Analyzing authentication logs...")
	authLogCheck, err := agent.AnalyzeAuthLogs([]string{"/var/log/auth.log", "/var/log/secure"})
	if err != nil {
		log.Printf("Auth log analysis failed: %v", err)
	} else {
		c.sendScanResult(authLogCheck)
		if authLogCheck.ThreatCount > 0 {
			log.Printf("⚠️  ALERT: %d brute force attempts detected!", authLogCheck.ThreatCount)
		}
	}

	log.Println("=== Security Scan Completed ===")
	return nil
}

// sendInventory sends inventory data to manager
func (c *AgentClient) sendInventory(inventory *agent.SystemInventory) error {
	resp, err := c.sendRequest("POST", "/api/v1/agents/inventory", inventory)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
		log.Println("Inventory sent successfully")
	}

	return nil
}

// sendScanResult sends scan results to manager
func (c *AgentClient) sendScanResult(result *agent.SecurityScanResult) error {
	resp, err := c.sendRequest("POST", "/api/v1/agents/scan-results", result)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
		log.Printf("Scan result (%s) sent successfully", result.Module)
	}

	return nil
}

// sendRequest sends an HTTP request to the manager
func (c *AgentClient) sendRequest(method, path string, data interface{}) (*http.Response, error) {
	url := c.config.ManagerURL + path

	var body io.Reader
	if data != nil {
		jsonData, err := json.Marshal(data)
		if err != nil {
			return nil, err
		}
		body = bytes.NewBuffer(jsonData)
	}

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", c.config.APIKey)

	return c.httpClient.Do(req)
}

// loadConfig loads agent configuration
func loadConfig(configFile string) (Config, error) {
	// Default configuration
	config := Config{
		ManagerURL:        "https://protei-manager:8443",
		HeartbeatInterval: 60,
		ScanSchedule:      "0 2 * * *", // Daily at 2 AM
	}

	// Try to load from file
	data, err := os.ReadFile(configFile)
	if err != nil {
		// Return default config if file doesn't exist
		log.Printf("Using default configuration (file not found: %s)", configFile)
		return config, nil
	}

	// Parse JSON config
	if err := json.Unmarshal(data, &config); err != nil {
		return config, fmt.Errorf("failed to parse config: %w", err)
	}

	return config, nil
}
