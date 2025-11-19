// +build windows

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
	"runtime"
	"time"

	"github.com/protei/security-suite/pkg/agent"
	"github.com/robfig/cron/v3"
)

const (
	Version = "1.0.0"
)

// Config holds agent configuration
type Config struct {
	ManagerURL        string
	APIKey            string
	ClientCert        string
	ClientKey         string
	CACert            string
	HeartbeatInterval int
	ScanSchedule      string
}

// AgentClient handles communication with the manager
type AgentClient struct {
	config     Config
	httpClient *http.Client
	agentID    string
}

func main() {
	// Parse command line flags
	configFile := flag.String("config", "C:\\ProgramData\\Protei\\agent.conf", "Configuration file path")
	flag.Parse()

	log.Printf("Protei Security Suite - Windows Agent v%s\n", Version)

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

	// Register with manager
	if err := client.Register(); err != nil {
		log.Printf("Warning: Failed to register with manager: %v", err)
	}

	// Start heartbeat
	go client.StartHeartbeat()

	// Setup scheduled scans
	if config.ScanSchedule != "" {
		client.SetupScheduledScans(config.ScanSchedule)
	}

	// Run initial security scan
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

	// Create HTTP client
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
	hostname, _ := os.Hostname()

	registrationData := map[string]interface{}{
		"agent_type": "windows",
		"hostname":   hostname,
		"version":    Version,
		"os_info": map[string]string{
			"os_type":    runtime.GOOS,
			"arch":       runtime.GOARCH,
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

// StartHeartbeat sends periodic heartbeats
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

// SetupScheduledScans configures scheduled scans
func (c *AgentClient) SetupScheduledScans(schedule string) {
	cronScheduler := cron.New()

	cronScheduler.AddFunc(schedule, func() {
		log.Println("Running scheduled security scan...")
		if err := c.RunFullSecurityScan(); err != nil {
			log.Printf("Scheduled scan failed: %v", err)
		}
	})

	cronScheduler.Start()
	log.Printf("Scheduled scans configured: %s", schedule)
}

// RunFullSecurityScan performs all Windows security checks
func (c *AgentClient) RunFullSecurityScan() error {
	log.Println("=== Starting Full Windows Security Scan ===")

	// 1. Windows Defender scan
	log.Println("[1/4] Running Windows Defender scan...")
	defenderScan, err := agent.RunWindowsDefenderScan()
	if err != nil {
		log.Printf("Defender scan failed: %v", err)
	} else {
		c.sendScanResult(defenderScan)
		if defenderScan.Status == "threats_found" {
			log.Printf("⚠️  ALERT: %d threats detected by Windows Defender!", defenderScan.ThreatCount)
		}
	}

	// 2. Task Scheduler check
	log.Println("[2/4] Checking Task Scheduler...")
	taskCheck, err := agent.CheckTaskScheduler()
	if err != nil {
		log.Printf("Task Scheduler check failed: %v", err)
	} else {
		c.sendScanResult(taskCheck)
		if taskCheck.SuspiciousCount > 0 {
			log.Printf("⚠️  WARNING: %d suspicious scheduled tasks found", taskCheck.SuspiciousCount)
		}
	}

	// 3. Startup items check
	log.Println("[3/4] Inspecting startup items...")
	startupCheck, err := agent.CheckStartupItems()
	if err != nil {
		log.Printf("Startup items check failed: %v", err)
	} else {
		c.sendScanResult(startupCheck)
		if startupCheck.SuspiciousCount > 0 {
			log.Printf("⚠️  WARNING: %d suspicious startup items found", startupCheck.SuspiciousCount)
		}
	}

	// 4. Event Viewer analysis
	log.Println("[4/4] Analyzing Event Viewer logs...")
	eventCheck, err := agent.AnalyzeEventViewer()
	if err != nil {
		log.Printf("Event Viewer analysis failed: %v", err)
	} else {
		c.sendScanResult(eventCheck)
		if eventCheck.ThreatCount > 0 {
			log.Printf("⚠️  ALERT: Suspicious activity detected in Event Viewer!")
		}
	}

	log.Println("=== Security Scan Completed ===")
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
	config := Config{
		ManagerURL:        "https://protei-manager:8443",
		HeartbeatInterval: 60,
		ScanSchedule:      "0 2 * * *",
	}

	data, err := os.ReadFile(configFile)
	if err != nil {
		log.Printf("Using default configuration (file not found: %s)", configFile)
		return config, nil
	}

	if err := json.Unmarshal(data, &config); err != nil {
		return config, fmt.Errorf("failed to parse config: %w", err)
	}

	return config, nil
}
