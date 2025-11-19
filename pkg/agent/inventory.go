package agent

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// SystemInventory represents system information
type SystemInventory struct {
	Hostname       string            `json:"hostname"`
	IPAddress      string            `json:"ip_address"`
	OSType         string            `json:"os_type"`
	OSName         string            `json:"os_name"`
	OSVersion      string            `json:"os_version"`
	OSArchitecture string            `json:"os_architecture"`
	Kernel         string            `json:"kernel"`
	Packages       []PackageInfo     `json:"packages,omitempty"`
	Services       []ServiceInfo     `json:"services,omitempty"`
	Users          []UserInfo        `json:"users,omitempty"`
	NetworkInfo    NetworkInfo       `json:"network_info"`
}

type PackageInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type ServiceInfo struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Enabled bool  `json:"enabled"`
}

type UserInfo struct {
	Username string `json:"username"`
	UID      string `json:"uid"`
	GID      string `json:"gid"`
	HomeDir  string `json:"home_dir"`
	Shell    string `json:"shell"`
}

type NetworkInfo struct {
	Interfaces     []NetworkInterface `json:"interfaces"`
	ListeningPorts []ListeningPort    `json:"listening_ports"`
}

type NetworkInterface struct {
	Name       string   `json:"name"`
	IPAddress  []string `json:"ip_addresses"`
	MACAddress string   `json:"mac_address"`
}

type ListeningPort struct {
	Protocol string `json:"protocol"`
	Port     string `json:"port"`
	Process  string `json:"process"`
	PID      string `json:"pid"`
}

// CollectInventory gathers system information
func CollectInventory() (*SystemInventory, error) {
	inventory := &SystemInventory{
		OSType:         runtime.GOOS,
		OSArchitecture: runtime.GOARCH,
	}

	var err error

	// Get hostname
	inventory.Hostname, err = os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("failed to get hostname: %w", err)
	}

	// Get OS information
	if runtime.GOOS == "linux" {
		inventory.OSName, inventory.OSVersion = getLinuxOSInfo()
		inventory.Kernel = getKernelVersion()
		inventory.Users = getLinuxUsers()
	}

	// Get IP address
	inventory.IPAddress = getPrimaryIPAddress()

	// Get network info
	inventory.NetworkInfo = getNetworkInfo()

	return inventory, nil
}

func getLinuxOSInfo() (string, string) {
	// Try /etc/os-release first
	data, err := os.ReadFile("/etc/os-release")
	if err == nil {
		lines := strings.Split(string(data), "\n")
		var name, version string
		for _, line := range lines {
			if strings.HasPrefix(line, "NAME=") {
				name = strings.Trim(strings.TrimPrefix(line, "NAME="), "\"")
			}
			if strings.HasPrefix(line, "VERSION=") {
				version = strings.Trim(strings.TrimPrefix(line, "VERSION="), "\"")
			}
		}
		return name, version
	}

	// Fallback to lsb_release
	cmd := exec.Command("lsb_release", "-d")
	output, err := cmd.Output()
	if err == nil {
		parts := strings.SplitN(string(output), ":", 2)
		if len(parts) == 2 {
			return strings.TrimSpace(parts[1]), ""
		}
	}

	return "Linux", "Unknown"
}

func getKernelVersion() string {
	cmd := exec.Command("uname", "-r")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

func getPrimaryIPAddress() string {
	cmd := exec.Command("hostname", "-I")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	ips := strings.Fields(string(output))
	if len(ips) > 0 {
		return ips[0]
	}
	return ""
}

func getLinuxUsers() []UserInfo {
	var users []UserInfo

	file, err := os.Open("/etc/passwd")
	if err != nil {
		return users
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ":")
		if len(parts) >= 7 {
			users = append(users, UserInfo{
				Username: parts[0],
				UID:      parts[2],
				GID:      parts[3],
				HomeDir:  parts[5],
				Shell:    parts[6],
			})
		}
	}

	return users
}

func getNetworkInfo() NetworkInfo {
	info := NetworkInfo{}

	// Get listening ports using ss
	info.ListeningPorts = getListeningPorts()

	return info
}

func getListeningPorts() []ListeningPort {
	var ports []ListeningPort

	// Use ss -tulnp to get listening ports
	cmd := exec.Command("ss", "-tulnp")
	output, err := cmd.Output()
	if err != nil {
		return ports
	}

	lines := strings.Split(string(output), "\n")
	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue // Skip header
		}

		fields := strings.Fields(line)
		if len(fields) >= 5 {
			protocol := fields[0]
			localAddr := fields[4]

			// Parse port from address (format: *:80 or 0.0.0.0:80)
			parts := strings.Split(localAddr, ":")
			if len(parts) >= 2 {
				port := parts[len(parts)-1]

				process := ""
				pid := ""
				if len(fields) >= 6 {
					// Parse process info (format: users:(("nginx",pid=1234,fd=6)))
					processInfo := fields[len(fields)-1]
					if strings.Contains(processInfo, "pid=") {
						// Extract process name and PID
						if idx := strings.Index(processInfo, "((\""); idx != -1 {
							processInfo = processInfo[idx+3:]
							if idx := strings.Index(processInfo, "\""); idx != -1 {
								process = processInfo[:idx]
							}
						}
						if idx := strings.Index(processInfo, "pid="); idx != -1 {
							pidStr := processInfo[idx+4:]
							if idx := strings.Index(pidStr, ","); idx != -1 {
								pid = pidStr[:idx]
							}
						}
					}
				}

				ports = append(ports, ListeningPort{
					Protocol: protocol,
					Port:     port,
					Process:  process,
					PID:      pid,
				})
			}
		}
	}

	return ports
}

// RunCommand executes a shell command and returns output
func RunCommand(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("command failed: %v - %s", err, stderr.String())
	}

	return out.String(), nil
}
