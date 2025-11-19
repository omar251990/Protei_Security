package scanner

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// ScanResult represents a network scan result
type ScanResult struct {
	IPAddress    string           `json:"ip_address"`
	Hostname     string           `json:"hostname"`
	IsAlive      bool             `json:"is_alive"`
	OpenPorts    []PortInfo       `json:"open_ports"`
	OSFingerprint string          `json:"os_fingerprint"`
	ResponseTime  int64           `json:"response_time_ms"`
}

// PortInfo represents information about an open port
type PortInfo struct {
	Port         int    `json:"port"`
	Protocol     string `json:"protocol"` // tcp or udp
	State        string `json:"state"`    // open, closed, filtered
	Service      string `json:"service"`
	Version      string `json:"version"`
	Banner       string `json:"banner"`
}

// ScanConfig holds scan configuration
type ScanConfig struct {
	Targets      []string
	PortRanges   []string
	Timeout      time.Duration
	Concurrency  int
	ScanTCP      bool
	ScanUDP      bool
	ServiceDetection bool
	OSDetection  bool
}

// Scanner performs network scanning
type Scanner struct {
	config ScanConfig
}

// NewScanner creates a new scanner instance
func NewScanner(config ScanConfig) *Scanner {
	return &Scanner{config: config}
}

// Scan performs network scanning on targets
func (s *Scanner) Scan() ([]ScanResult, error) {
	var results []ScanResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Parse targets and create IP list
	ips, err := s.parseTargets()
	if err != nil {
		return nil, err
	}

	// Create worker pool
	ipChan := make(chan string, len(ips))
	for _, ip := range ips {
		ipChan <- ip
	}
	close(ipChan)

	// Start workers
	for i := 0; i < s.config.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range ipChan {
				result := s.scanHost(ip)
				if result.IsAlive || len(result.OpenPorts) > 0 {
					mu.Lock()
					results = append(results, result)
					mu.Unlock()
				}
			}
		}()
	}

	wg.Wait()
	return results, nil
}

// parseTargets parses target specifications and returns list of IPs
func (s *Scanner) parseTargets() ([]string, error) {
	var ips []string

	for _, target := range s.config.Targets {
		// Check if target is CIDR notation
		if _, ipnet, err := net.ParseCIDR(target); err == nil {
			// Expand CIDR to individual IPs
			for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
				ips = append(ips, ip.String())
			}
		} else if ip := net.ParseIP(target); ip != nil {
			// Single IP address
			ips = append(ips, target)
		} else if addrs, err := net.LookupHost(target); err == nil {
			// Hostname resolution
			ips = append(ips, addrs...)
		} else {
			return nil, fmt.Errorf("invalid target: %s", target)
		}
	}

	return ips, nil
}

// scanHost scans a single host
func (s *Scanner) scanHost(ip string) ScanResult {
	start := time.Now()
	result := ScanResult{
		IPAddress: ip,
		OpenPorts: []PortInfo{},
	}

	// Check if host is alive (ping)
	result.IsAlive = s.isHostAlive(ip)

	if !result.IsAlive {
		return result
	}

	// Reverse DNS lookup for hostname
	names, err := net.LookupAddr(ip)
	if err == nil && len(names) > 0 {
		result.Hostname = names[0]
	}

	// Scan ports
	ports := s.parsePorts()
	if s.config.ScanTCP {
		result.OpenPorts = append(result.OpenPorts, s.scanTCPPorts(ip, ports)...)
	}

	// Service detection on open ports
	if s.config.ServiceDetection {
		for i := range result.OpenPorts {
			s.detectService(&result.OpenPorts[i], ip)
		}
	}

	result.ResponseTime = time.Since(start).Milliseconds()
	return result
}

// isHostAlive checks if host responds to ping
func (s *Scanner) isHostAlive(ip string) bool {
	// Try TCP connect to common ports as ping alternative
	commonPorts := []int{80, 443, 22, 3389}

	for _, port := range commonPorts {
		address := fmt.Sprintf("%s:%d", ip, port)
		conn, err := net.DialTimeout("tcp", address, 2*time.Second)
		if err == nil {
			conn.Close()
			return true
		}
	}

	return false
}

// parsePorts parses port ranges into list of ports
func (s *Scanner) parsePorts() []int {
	var ports []int

	// Common default ports if none specified
	if len(s.config.PortRanges) == 0 {
		return []int{21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 8080, 8443}
	}

	for _, portRange := range s.config.PortRanges {
		var start, end int
		// Parse range (e.g., "1-1024" or single port "80")
		if _, err := fmt.Sscanf(portRange, "%d-%d", &start, &end); err == nil {
			for p := start; p <= end && p <= 65535; p++ {
				ports = append(ports, p)
			}
		} else if _, err := fmt.Sscanf(portRange, "%d", &start); err == nil {
			ports = append(ports, start)
		}
	}

	return ports
}

// scanTCPPorts scans TCP ports on a host
func (s *Scanner) scanTCPPorts(ip string, ports []int) []PortInfo {
	var openPorts []PortInfo
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Limit concurrent port scans
	sem := make(chan struct{}, 100)

	for _, port := range ports {
		wg.Add(1)
		sem <- struct{}{}

		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()

			address := fmt.Sprintf("%s:%d", ip, p)
			conn, err := net.DialTimeout("tcp", address, s.config.Timeout)

			if err == nil {
				conn.Close()

				portInfo := PortInfo{
					Port:     p,
					Protocol: "tcp",
					State:    "open",
					Service:  getServiceName(p),
				}

				mu.Lock()
				openPorts = append(openPorts, portInfo)
				mu.Unlock()
			}
		}(port)
	}

	wg.Wait()
	return openPorts
}

// detectService attempts to detect service version
func (s *Scanner) detectService(portInfo *PortInfo, ip string) {
	address := fmt.Sprintf("%s:%d", ip, portInfo.Port)
	conn, err := net.DialTimeout("tcp", address, s.config.Timeout)
	if err != nil {
		return
	}
	defer conn.Close()

	// Set read deadline
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Try to grab banner
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err == nil && n > 0 {
		portInfo.Banner = string(buffer[:n])
		portInfo.Version = parseBanner(portInfo.Banner, portInfo.Port)
	}

	// For HTTP/HTTPS, send HTTP request
	if portInfo.Port == 80 || portInfo.Port == 443 || portInfo.Port == 8080 || portInfo.Port == 8443 {
		conn.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
		n, err := conn.Read(buffer)
		if err == nil && n > 0 {
			portInfo.Banner = string(buffer[:n])
			portInfo.Version = parseBanner(portInfo.Banner, portInfo.Port)
		}
	}
}

// getServiceName returns common service name for port
func getServiceName(port int) string {
	services := map[int]string{
		21:   "ftp",
		22:   "ssh",
		23:   "telnet",
		25:   "smtp",
		53:   "dns",
		80:   "http",
		110:  "pop3",
		135:  "msrpc",
		139:  "netbios-ssn",
		143:  "imap",
		443:  "https",
		445:  "microsoft-ds",
		993:  "imaps",
		995:  "pop3s",
		1433: "mssql",
		3306: "mysql",
		3389: "rdp",
		5432: "postgresql",
		5900: "vnc",
		8080: "http-proxy",
		8443: "https-alt",
	}

	if service, ok := services[port]; ok {
		return service
	}

	return "unknown"
}

// parseBanner extracts version information from banner
func parseBanner(banner string, port int) string {
	// Simple banner parsing - can be enhanced with regex patterns
	if len(banner) > 100 {
		banner = banner[:100]
	}
	return banner
}

// inc increments an IP address
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// DetectWeakProtocols identifies insecure protocols
func DetectWeakProtocols(results []ScanResult) []string {
	var weakProtocols []string
	seen := make(map[string]bool)

	weakServices := map[string]string{
		"telnet": "Telnet (unencrypted)",
		"ftp":    "FTP (unencrypted)",
		"http":   "HTTP (unencrypted web)",
	}

	for _, result := range results {
		for _, port := range result.OpenPorts {
			if desc, ok := weakServices[port.Service]; ok {
				key := fmt.Sprintf("%s:%d - %s", result.IPAddress, port.Port, desc)
				if !seen[key] {
					weakProtocols = append(weakProtocols, key)
					seen[key] = true
				}
			}

			// Check for SMBv1 (port 445/139)
			if port.Port == 445 || port.Port == 139 {
				key := fmt.Sprintf("%s:%d - SMBv1 (vulnerable)", result.IPAddress, port.Port)
				if !seen[key] {
					weakProtocols = append(weakProtocols, key)
					seen[key] = true
				}
			}
		}
	}

	return weakProtocols
}
