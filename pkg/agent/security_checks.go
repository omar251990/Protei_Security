package agent

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// SecurityScanResult represents security scan results
type SecurityScanResult struct {
	Module          string                 `json:"module"`
	Status          string                 `json:"status"` // clean, threats_found, suspicious, error
	Findings        map[string]interface{} `json:"findings"`
	ThreatCount     int                    `json:"threat_count"`
	SuspiciousCount int                    `json:"suspicious_count"`
	ScanDuration    int                    `json:"scan_duration_seconds"`
	ScannedAt       time.Time              `json:"scanned_at"`
	RawOutput       string                 `json:"raw_output,omitempty"`
}

// MalwareScanResult represents malware scan findings
type MalwareScanResult struct {
	InfectedFiles      []string `json:"infected_files"`
	MalwareSignatures  []string `json:"malware_signatures"`
	ScannedFiles       int      `json:"scanned_files"`
	InfectedCount      int      `json:"infected_count"`
}

// RootkitScanResult represents rootkit detection findings
type RootkitScanResult struct {
	RootkitIndicators  []string `json:"rootkit_indicators"`
	SuspiciousFiles    []string `json:"suspicious_files"`
	Warning            []string `json:"warnings"`
}

// CrontabCheckResult represents crontab analysis
type CrontabCheckResult struct {
	TotalJobs         int      `json:"total_jobs"`
	SuspiciousJobs    []string `json:"suspicious_jobs"`
	UserCrontabs      map[string][]string `json:"user_crontabs"`
}

// UserCheckResult represents user account audit
type UserCheckResult struct {
	TotalUsers        int      `json:"total_users"`
	SuspiciousUsers   []string `json:"suspicious_users"`
	UsersWithoutPassword []string `json:"users_without_password"`
	RootUsers         []string `json:"root_users"`
}

// FileIntegrityResult represents file integrity check
type FileIntegrityResult struct {
	SuspiciousFiles   []string `json:"suspicious_files"`
	NewFiles          []string `json:"new_files"`
	ModifiedFiles     []string `json:"modified_files"`
	WorldWritableFiles []string `json:"world_writable_files"`
}

// AuthLogResult represents auth log analysis
type AuthLogResult struct {
	FailedLogins      int                    `json:"failed_logins"`
	SuccessfulLogins  int                    `json:"successful_logins"`
	UnknownLogins     []map[string]string    `json:"unknown_logins"`
	SuspiciousIPs     []string               `json:"suspicious_ips"`
	BruteForceAttempts int                   `json:"brute_force_attempts"`
}

// RunMalwareScan performs malware scanning using ClamAV
func RunMalwareScan(directories []string) (*SecurityScanResult, error) {
	start := time.Now()
	result := &SecurityScanResult{
		Module:    "malware",
		Status:    "clean",
		Findings:  make(map[string]interface{}),
		ScannedAt: start,
	}

	// Check if clamscan is available
	if _, err := exec.LookPath("clamscan"); err != nil {
		result.Status = "error"
		result.Findings["error"] = "ClamAV not installed"
		return result, nil
	}

	malwareResult := &MalwareScanResult{
		InfectedFiles:     []string{},
		MalwareSignatures: []string{},
	}

	// Update virus database first
	exec.Command("freshclam").Run()

	// Scan directories
	for _, dir := range directories {
		cmd := exec.Command("clamscan", "-r", "-i", dir)
		output, _ := cmd.CombinedOutput()

		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "FOUND") {
				parts := strings.Split(line, ":")
				if len(parts) >= 2 {
					malwareResult.InfectedFiles = append(malwareResult.InfectedFiles, strings.TrimSpace(parts[0]))
					malwareResult.MalwareSignatures = append(malwareResult.MalwareSignatures, strings.TrimSpace(parts[1]))
				}
			}
			if strings.Contains(line, "Scanned files:") {
				numStr := strings.TrimSpace(strings.Split(line, ":")[1])
				malwareResult.ScannedFiles, _ = strconv.Atoi(numStr)
			}
		}
	}

	malwareResult.InfectedCount = len(malwareResult.InfectedFiles)
	result.Findings["malware"] = malwareResult
	result.ThreatCount = malwareResult.InfectedCount

	if malwareResult.InfectedCount > 0 {
		result.Status = "threats_found"
	}

	result.ScanDuration = int(time.Since(start).Seconds())
	return result, nil
}

// RunRootkitScan performs rootkit detection using chkrootkit and rkhunter
func RunRootkitScan() (*SecurityScanResult, error) {
	start := time.Now()
	result := &SecurityScanResult{
		Module:    "rootkit",
		Status:    "clean",
		Findings:  make(map[string]interface{}),
		ScannedAt: start,
	}

	rootkitResult := &RootkitScanResult{
		RootkitIndicators: []string{},
		SuspiciousFiles:   []string{},
		Warning:           []string{},
	}

	// Run chkrootkit
	if _, err := exec.LookPath("chkrootkit"); err == nil {
		cmd := exec.Command("chkrootkit")
		output, _ := cmd.CombinedOutput()
		result.RawOutput += "=== chkrootkit ===\n" + string(output) + "\n"

		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "INFECTED") || strings.Contains(line, "infected") {
				rootkitResult.RootkitIndicators = append(rootkitResult.RootkitIndicators, line)
			} else if strings.Contains(line, "suspicious") || strings.Contains(line, "Warning") {
				rootkitResult.Warning = append(rootkitResult.Warning, line)
			}
		}
	}

	// Run rkhunter
	if _, err := exec.LookPath("rkhunter"); err == nil {
		cmd := exec.Command("rkhunter", "--check", "--skip-keypress", "--report-warnings-only")
		output, _ := cmd.CombinedOutput()
		result.RawOutput += "\n=== rkhunter ===\n" + string(output) + "\n"

		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "Warning") || strings.Contains(line, "warning") {
				rootkitResult.Warning = append(rootkitResult.Warning, line)
			}
		}
	}

	result.Findings["rootkit"] = rootkitResult
	result.ThreatCount = len(rootkitResult.RootkitIndicators)
	result.SuspiciousCount = len(rootkitResult.Warning)

	if result.ThreatCount > 0 {
		result.Status = "threats_found"
	} else if result.SuspiciousCount > 0 {
		result.Status = "suspicious"
	}

	result.ScanDuration = int(time.Since(start).Seconds())
	return result, nil
}

// CheckCrontab analyzes crontab for suspicious entries
func CheckCrontab() (*SecurityScanResult, error) {
	start := time.Now()
	result := &SecurityScanResult{
		Module:    "crontab",
		Status:    "clean",
		Findings:  make(map[string]interface{}),
		ScannedAt: start,
	}

	crontabResult := &CrontabCheckResult{
		SuspiciousJobs: []string{},
		UserCrontabs:   make(map[string][]string),
	}

	// Suspicious patterns in cron jobs
	suspiciousPatterns := []string{
		"wget", "curl", "nc ", "netcat", "/tmp/", "/dev/shm/",
		"base64", "bash -i", "sh -i", "/dev/tcp/",
		"perl -e", "python -c", "ruby -e",
	}

	// Check system crontabs
	systemCronDirs := []string{
		"/etc/cron.d/",
		"/etc/cron.daily/",
		"/etc/cron.hourly/",
		"/etc/cron.monthly/",
		"/etc/cron.weekly/",
	}

	for _, dir := range systemCronDirs {
		files, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, file := range files {
			if file.IsDir() {
				continue
			}
			content, err := os.ReadFile(filepath.Join(dir, file.Name()))
			if err != nil {
				continue
			}

			lines := strings.Split(string(content), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}

				crontabResult.TotalJobs++

				// Check for suspicious patterns
				for _, pattern := range suspiciousPatterns {
					if strings.Contains(strings.ToLower(line), strings.ToLower(pattern)) {
						crontabResult.SuspiciousJobs = append(crontabResult.SuspiciousJobs,
							fmt.Sprintf("%s/%s: %s", dir, file.Name(), line))
						break
					}
				}
			}
		}
	}

	// Check /etc/crontab
	if content, err := os.ReadFile("/etc/crontab"); err == nil {
		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			crontabResult.TotalJobs++

			for _, pattern := range suspiciousPatterns {
				if strings.Contains(strings.ToLower(line), strings.ToLower(pattern)) {
					crontabResult.SuspiciousJobs = append(crontabResult.SuspiciousJobs,
						fmt.Sprintf("/etc/crontab: %s", line))
					break
				}
			}
		}
	}

	// Check user crontabs
	cmd := exec.Command("bash", "-c", "for user in $(cut -f1 -d: /etc/passwd); do crontab -u $user -l 2>/dev/null; done")
	output, _ := cmd.Output()
	if len(output) > 0 {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			crontabResult.TotalJobs++

			for _, pattern := range suspiciousPatterns {
				if strings.Contains(strings.ToLower(line), strings.ToLower(pattern)) {
					crontabResult.SuspiciousJobs = append(crontabResult.SuspiciousJobs, line)
					break
				}
			}
		}
	}

	result.Findings["crontab"] = crontabResult
	result.SuspiciousCount = len(crontabResult.SuspiciousJobs)

	if result.SuspiciousCount > 0 {
		result.Status = "suspicious"
	}

	result.ScanDuration = int(time.Since(start).Seconds())
	return result, nil
}

// CheckUsers analyzes user accounts for suspicious entries
func CheckUsers() (*SecurityScanResult, error) {
	start := time.Now()
	result := &SecurityScanResult{
		Module:    "users",
		Status:    "clean",
		Findings:  make(map[string]interface{}),
		ScannedAt: start,
	}

	userResult := &UserCheckResult{
		SuspiciousUsers:      []string{},
		UsersWithoutPassword: []string{},
		RootUsers:            []string{},
	}

	// Parse /etc/passwd
	passwdFile, err := os.Open("/etc/passwd")
	if err != nil {
		return nil, err
	}
	defer passwdFile.Close()

	scanner := bufio.NewScanner(passwdFile)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ":")
		if len(parts) < 7 {
			continue
		}

		username := parts[0]
		uid := parts[2]
		shell := parts[6]

		userResult.TotalUsers++

		// Check for UID 0 (root equivalent)
		if uid == "0" && username != "root" {
			userResult.RootUsers = append(userResult.RootUsers, username)
			userResult.SuspiciousUsers = append(userResult.SuspiciousUsers,
				fmt.Sprintf("%s has UID 0 (root privileges)", username))
		}

		// Check for users with login shell but unusual names
		if shell != "/usr/sbin/nologin" && shell != "/bin/false" && shell != "/sbin/nologin" {
			if !isKnownSystemUser(username) {
				// Additional checks for suspicious usernames
				if strings.Contains(username, "..") || strings.Contains(username, "$") {
					userResult.SuspiciousUsers = append(userResult.SuspiciousUsers,
						fmt.Sprintf("%s has suspicious username pattern", username))
				}
			}
		}
	}

	// Check /etc/shadow for users without passwords
	shadowFile, err := os.Open("/etc/shadow")
	if err == nil {
		defer shadowFile.Close()
		scanner := bufio.NewScanner(shadowFile)
		for scanner.Scan() {
			line := scanner.Text()
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				username := parts[0]
				password := parts[1]

				// Empty password or disabled
				if password == "" || password == "!" || password == "*" {
					// Only flag if user has login shell
					if !isSystemUser(username) {
						userResult.UsersWithoutPassword = append(userResult.UsersWithoutPassword, username)
					}
				}
			}
		}
	}

	result.Findings["users"] = userResult
	result.SuspiciousCount = len(userResult.SuspiciousUsers)
	result.ThreatCount = len(userResult.RootUsers)

	if result.ThreatCount > 0 || result.SuspiciousCount > 0 {
		result.Status = "suspicious"
	}

	result.ScanDuration = int(time.Since(start).Seconds())
	return result, nil
}

// CheckFileIntegrity checks for suspicious files in critical directories
func CheckFileIntegrity(directories []string) (*SecurityScanResult, error) {
	start := time.Now()
	result := &SecurityScanResult{
		Module:    "file_integrity",
		Status:    "clean",
		Findings:  make(map[string]interface{}),
		ScannedAt: start,
	}

	fileResult := &FileIntegrityResult{
		SuspiciousFiles:    []string{},
		WorldWritableFiles: []string{},
	}

	// Check each directory
	for _, dir := range directories {
		err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil // Skip files we can't access
			}

			if info.IsDir() {
				return nil
			}

			// Check for world-writable files
			mode := info.Mode()
			if mode.Perm()&0002 != 0 {
				fileResult.WorldWritableFiles = append(fileResult.WorldWritableFiles, path)
			}

			// Check for suspicious file patterns
			basename := filepath.Base(path)
			if isSuspiciousFilename(basename) {
				fileResult.SuspiciousFiles = append(fileResult.SuspiciousFiles, path)
			}

			return nil
		})

		if err != nil {
			continue
		}
	}

	result.Findings["file_integrity"] = fileResult
	result.SuspiciousCount = len(fileResult.SuspiciousFiles) + len(fileResult.WorldWritableFiles)

	if result.SuspiciousCount > 0 {
		result.Status = "suspicious"
	}

	result.ScanDuration = int(time.Since(start).Seconds())
	return result, nil
}

// AnalyzeAuthLogs parses authentication logs for suspicious activity
func AnalyzeAuthLogs(logFiles []string) (*SecurityScanResult, error) {
	start := time.Now()
	result := &SecurityScanResult{
		Module:    "auth_logs",
		Status:    "clean",
		Findings:  make(map[string]interface{}),
		ScannedAt: start,
	}

	authResult := &AuthLogResult{
		UnknownLogins:  []map[string]string{},
		SuspiciousIPs:  []string{},
	}

	failedLoginsPerIP := make(map[string]int)

	// Patterns to detect
	failedSSHPattern := regexp.MustCompile(`Failed password for (\w+) from ([\d.]+)`)
	acceptedSSHPattern := regexp.MustCompile(`Accepted password for (\w+) from ([\d.]+)`)
	invalidUserPattern := regexp.MustCompile(`Invalid user (\w+) from ([\d.]+)`)

	for _, logFile := range logFiles {
		file, err := os.Open(logFile)
		if err != nil {
			continue
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()

			// Check for failed logins
			if matches := failedSSHPattern.FindStringSubmatch(line); matches != nil {
				authResult.FailedLogins++
				ip := matches[2]
				failedLoginsPerIP[ip]++
			}

			// Check for successful logins
			if matches := acceptedSSHPattern.FindStringSubmatch(line); matches != nil {
				authResult.SuccessfulLogins++
			}

			// Check for invalid users
			if matches := invalidUserPattern.FindStringSubmatch(line); matches != nil {
				username := matches[1]
				ip := matches[2]
				authResult.UnknownLogins = append(authResult.UnknownLogins, map[string]string{
					"username": username,
					"ip":       ip,
					"log_line": line,
				})
			}
		}
	}

	// Detect brute force attempts (more than 10 failed logins from same IP)
	for ip, count := range failedLoginsPerIP {
		if count >= 10 {
			authResult.BruteForceAttempts++
			authResult.SuspiciousIPs = append(authResult.SuspiciousIPs, fmt.Sprintf("%s (%d failed attempts)", ip, count))
		}
	}

	result.Findings["auth_logs"] = authResult
	result.SuspiciousCount = len(authResult.UnknownLogins) + authResult.BruteForceAttempts

	if authResult.BruteForceAttempts > 0 {
		result.Status = "threats_found"
		result.ThreatCount = authResult.BruteForceAttempts
	} else if result.SuspiciousCount > 0 {
		result.Status = "suspicious"
	}

	result.ScanDuration = int(time.Since(start).Seconds())
	return result, nil
}

// Helper functions

func isKnownSystemUser(username string) bool {
	systemUsers := []string{
		"root", "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail", "news",
		"uucp", "proxy", "www-data", "backup", "list", "irc", "gnats", "nobody",
		"systemd-network", "systemd-resolve", "messagebus", "syslog", "uuidd",
		"tcpdump", "landscape", "pollinate", "sshd", "ubuntu", "lxd",
	}

	for _, known := range systemUsers {
		if username == known {
			return true
		}
	}
	return false
}

func isSystemUser(username string) bool {
	return isKnownSystemUser(username)
}

func isSuspiciousFilename(filename string) bool {
	suspiciousPatterns := []string{
		"..", "~", ".sh.bak", ".old", ".swp",
	}

	lowerFilename := strings.ToLower(filename)

	// Check for hidden executable scripts
	if strings.HasPrefix(filename, ".") && (strings.HasSuffix(lowerFilename, ".sh") ||
		strings.HasSuffix(lowerFilename, ".py") || strings.HasSuffix(lowerFilename, ".pl")) {
		return true
	}

	for _, pattern := range suspiciousPatterns {
		if strings.Contains(filename, pattern) {
			return true
		}
	}

	return false
}
