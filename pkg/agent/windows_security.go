// +build windows

package agent

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// WindowsSecurityScan represents Windows-specific security checks
type WindowsSecurityScan struct {
	DefenderScan      *DefenderScanResult      `json:"defender_scan"`
	TaskScheduler     *TaskSchedulerResult     `json:"task_scheduler"`
	StartupItems      *StartupItemsResult      `json:"startup_items"`
	EventViewerAlerts *EventViewerResult       `json:"event_viewer_alerts"`
}

// DefenderScanResult holds Windows Defender scan results
type DefenderScanResult struct {
	ScanStatus        string   `json:"scan_status"`
	ThreatsDetected   int      `json:"threats_detected"`
	ThreatNames       []string `json:"threat_names"`
	LastScanTime      string   `json:"last_scan_time"`
	DefinitionVersion string   `json:"definition_version"`
}

// TaskSchedulerResult holds suspicious scheduled tasks
type TaskSchedulerResult struct {
	TotalTasks       int      `json:"total_tasks"`
	SuspiciousTasks  []string `json:"suspicious_tasks"`
}

// StartupItemsResult holds startup entries
type StartupItemsResult struct {
	RegistryStartup  []string `json:"registry_startup"`
	FolderStartup    []string `json:"folder_startup"`
	SuspiciousItems  []string `json:"suspicious_items"`
}

// EventViewerResult holds Event Viewer analysis
type EventViewerResult struct {
	FailedLogons            int              `json:"failed_logons"`
	SuccessfulRDPLogons     []string         `json:"successful_rdp_logons"`
	SuspiciousPowerShell    []string         `json:"suspicious_powershell"`
	SuspiciousProcesses     []string         `json:"suspicious_processes"`
	UnknownLogons           []map[string]string `json:"unknown_logons"`
}

// RunWindowsDefenderScan triggers Windows Defender scan
func RunWindowsDefenderScan() (*SecurityScanResult, error) {
	start := time.Now()
	result := &SecurityScanResult{
		Module:    "windows_defender",
		Status:    "clean",
		Findings:  make(map[string]interface{}),
		ScannedAt: start,
	}

	defenderResult := &DefenderScanResult{
		ThreatNames: []string{},
	}

	// Update Windows Defender definitions
	psScript := `Update-MpSignature -ErrorAction SilentlyContinue`
	runPowerShell(psScript)

	// Get current threat status
	psScript = `
		$status = Get-MpThreatDetection -ErrorAction SilentlyContinue
		if ($status) {
			$status | ConvertTo-Json
		} else {
			@{ThreatsDetected = 0} | ConvertTo-Json
		}
	`

	output, err := runPowerShell(psScript)
	if err == nil {
		var threats []map[string]interface{}
		json.Unmarshal([]byte(output), &threats)
		defenderResult.ThreatsDetected = len(threats)

		for _, threat := range threats {
			if name, ok := threat["ThreatName"].(string); ok {
				defenderResult.ThreatNames = append(defenderResult.ThreatNames, name)
			}
		}
	}

	// Trigger quick scan
	psScript = `Start-MpScan -ScanType QuickScan -ErrorAction SilentlyContinue`
	runPowerShell(psScript)

	// Get scan status
	psScript = `
		$pref = Get-MpComputerStatus
		@{
			LastQuickScanTime = $pref.QuickScanStartTime
			SignatureVersion = $pref.AntivirusSignatureVersion
		} | ConvertTo-Json
	`

	output, err = runPowerShell(psScript)
	if err == nil {
		var status map[string]string
		json.Unmarshal([]byte(output), &status)
		defenderResult.LastScanTime = status["LastQuickScanTime"]
		defenderResult.DefinitionVersion = status["SignatureVersion"]
	}

	defenderResult.ScanStatus = "completed"
	result.Findings["defender"] = defenderResult
	result.ThreatCount = defenderResult.ThreatsDetected

	if result.ThreatCount > 0 {
		result.Status = "threats_found"
	}

	result.ScanDuration = int(time.Since(start).Seconds())
	return result, nil
}

// CheckTaskScheduler analyzes scheduled tasks for malicious entries
func CheckTaskScheduler() (*SecurityScanResult, error) {
	start := time.Now()
	result := &SecurityScanResult{
		Module:    "task_scheduler",
		Status:    "clean",
		Findings:  make(map[string]interface{}),
		ScannedAt: start,
	}

	taskResult := &TaskSchedulerResult{
		SuspiciousTasks: []string{},
	}

	// Get all scheduled tasks
	psScript := `
		Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} |
		Select-Object TaskName, TaskPath, @{Name='Actions';Expression={$_.Actions.Execute + ' ' + $_.Actions.Arguments}} |
		ConvertTo-Json
	`

	output, err := runPowerShell(psScript)
	if err != nil {
		result.Status = "error"
		result.Findings["error"] = err.Error()
		return result, nil
	}

	var tasks []map[string]interface{}
	json.Unmarshal([]byte(output), &tasks)
	taskResult.TotalTasks = len(tasks)

	// Suspicious patterns in task actions
	suspiciousPatterns := []string{
		"powershell", "cmd.exe", "wscript", "cscript",
		"certutil", "bitsadmin", "mshta", "regsvr32",
		"rundll32", "downloadfile", "invoke-webrequest",
		"http://", "https://", "\\\\", "temp\\", "appdata\\",
	}

	for _, task := range tasks {
		taskName := fmt.Sprintf("%v", task["TaskName"])
		actions := strings.ToLower(fmt.Sprintf("%v", task["Actions"]))

		for _, pattern := range suspiciousPatterns {
			if strings.Contains(actions, strings.ToLower(pattern)) {
				taskResult.SuspiciousTasks = append(taskResult.SuspiciousTasks,
					fmt.Sprintf("%s: %s", taskName, actions))
				break
			}
		}
	}

	result.Findings["tasks"] = taskResult
	result.SuspiciousCount = len(taskResult.SuspiciousTasks)

	if result.SuspiciousCount > 0 {
		result.Status = "suspicious"
	}

	result.ScanDuration = int(time.Since(start).Seconds())
	return result, nil
}

// CheckStartupItems inspects startup entries
func CheckStartupItems() (*SecurityScanResult, error) {
	start := time.Now()
	result := &SecurityScanResult{
		Module:    "startup_items",
		Status:    "clean",
		Findings:  make(map[string]interface{}),
		ScannedAt: start,
	}

	startupResult := &StartupItemsResult{
		RegistryStartup: []string{},
		FolderStartup:   []string{},
		SuspiciousItems: []string{},
	}

	// Check registry startup locations
	registryPaths := []string{
		"HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
		"HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
		"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
		"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
	}

	for _, regPath := range registryPaths {
		psScript := fmt.Sprintf(`
			Get-ItemProperty -Path '%s' -ErrorAction SilentlyContinue |
			Select-Object -Property * -ExcludeProperty PS* |
			ConvertTo-Json
		`, regPath)

		output, err := runPowerShell(psScript)
		if err == nil && output != "" {
			startupResult.RegistryStartup = append(startupResult.RegistryStartup,
				fmt.Sprintf("%s: %s", regPath, output))
		}
	}

	// Check startup folders
	psScript := `
		$startupPaths = @(
			"$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
			"$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
		)
		$items = @()
		foreach ($path in $startupPaths) {
			if (Test-Path $path) {
				Get-ChildItem -Path $path | ForEach-Object {
					$items += @{Path = $path; File = $_.Name}
				}
			}
		}
		$items | ConvertTo-Json
	`

	output, err := runPowerShell(psScript)
	if err == nil && output != "" {
		startupResult.FolderStartup = append(startupResult.FolderStartup, output)
	}

	// Analyze for suspicious patterns
	allStartup := strings.Join(append(startupResult.RegistryStartup, startupResult.FolderStartup...), " ")
	suspiciousPatterns := []string{
		"temp\\", "appdata\\roaming", "\\users\\public\\",
		"powershell", "cmd.exe", "wscript", "cscript",
		".vbs", ".bat", ".ps1", "certutil", "bitsadmin",
	}

	for _, pattern := range suspiciousPatterns {
		if strings.Contains(strings.ToLower(allStartup), strings.ToLower(pattern)) {
			startupResult.SuspiciousItems = append(startupResult.SuspiciousItems,
				fmt.Sprintf("Suspicious pattern found: %s", pattern))
		}
	}

	result.Findings["startup"] = startupResult
	result.SuspiciousCount = len(startupResult.SuspiciousItems)

	if result.SuspiciousCount > 0 {
		result.Status = "suspicious"
	}

	result.ScanDuration = int(time.Since(start).Seconds())
	return result, nil
}

// AnalyzeEventViewer analyzes Windows Event Viewer logs
func AnalyzeEventViewer() (*SecurityScanResult, error) {
	start := time.Now()
	result := &SecurityScanResult{
		Module:    "event_viewer",
		Status:    "clean",
		Findings:  make(map[string]interface{}),
		ScannedAt: start,
	}

	eventResult := &EventViewerResult{
		SuccessfulRDPLogons:  []string{},
		SuspiciousPowerShell: []string{},
		SuspiciousProcesses:  []string{},
		UnknownLogons:        []map[string]string{},
	}

	// Check failed logon attempts (Event ID 4625)
	psScript := `
		$yesterday = (Get-Date).AddDays(-1)
		$events = Get-WinEvent -FilterHashtable @{
			LogName='Security';
			ID=4625;
			StartTime=$yesterday
		} -MaxEvents 100 -ErrorAction SilentlyContinue
		$events.Count
	`

	output, err := runPowerShell(psScript)
	if err == nil {
		fmt.Sscanf(output, "%d", &eventResult.FailedLogons)
	}

	// Check successful RDP logons (Event ID 4624 with LogonType 10)
	psScript = `
		$yesterday = (Get-Date).AddDays(-1)
		$events = Get-WinEvent -FilterHashtable @{
			LogName='Security';
			ID=4624;
			StartTime=$yesterday
		} -MaxEvents 50 -ErrorAction SilentlyContinue

		$rdpLogons = @()
		foreach ($event in $events) {
			$xml = [xml]$event.ToXml()
			$logonType = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'LogonType'} | Select-Object -ExpandProperty '#text'
			if ($logonType -eq '10') {
				$username = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'} | Select-Object -ExpandProperty '#text'
				$ipAddress = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'IpAddress'} | Select-Object -ExpandProperty '#text'
				$rdpLogons += "$username from $ipAddress at $($event.TimeCreated)"
			}
		}
		$rdpLogons | ConvertTo-Json
	`

	output, err = runPowerShell(psScript)
	if err == nil && output != "" {
		json.Unmarshal([]byte(output), &eventResult.SuccessfulRDPLogons)
	}

	// Check PowerShell script block logging (Event ID 4104)
	psScript = `
		$yesterday = (Get-Date).AddDays(-1)
		$events = Get-WinEvent -FilterHashtable @{
			LogName='Microsoft-Windows-PowerShell/Operational';
			ID=4104;
			StartTime=$yesterday
		} -MaxEvents 50 -ErrorAction SilentlyContinue

		$suspicious = @()
		$patterns = @('Invoke-Expression', 'downloadstring', 'invoke-webrequest',
					  'net.webclient', 'iex', 'bypass', 'encoded')

		foreach ($event in $events) {
			$message = $event.Message
			foreach ($pattern in $patterns) {
				if ($message -like "*$pattern*") {
					$suspicious += $message.Substring(0, [Math]::Min(200, $message.Length))
					break
				}
			}
		}
		$suspicious | ConvertTo-Json
	`

	output, err = runPowerShell(psScript)
	if err == nil && output != "" {
		json.Unmarshal([]byte(output), &eventResult.SuspiciousPowerShell)
	}

	// Check process creation events (Event ID 4688) for suspicious executables
	psScript = `
		$yesterday = (Get-Date).AddDays(-1)
		$events = Get-WinEvent -FilterHashtable @{
			LogName='Security';
			ID=4688;
			StartTime=$yesterday
		} -MaxEvents 100 -ErrorAction SilentlyContinue

		$suspicious = @()
		$patterns = @('cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe',
					  'certutil.exe', 'bitsadmin.exe', 'mshta.exe')

		foreach ($event in $events) {
			$xml = [xml]$event.ToXml()
			$process = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'NewProcessName'} | Select-Object -ExpandProperty '#text'
			foreach ($pattern in $patterns) {
				if ($process -like "*$pattern*") {
					$suspicious += "$process at $($event.TimeCreated)"
					break
				}
			}
		}
		$suspicious | Select-Object -First 20 | ConvertTo-Json
	`

	output, err = runPowerShell(psScript)
	if err == nil && output != "" {
		json.Unmarshal([]byte(output), &eventResult.SuspiciousProcesses)
	}

	result.Findings["events"] = eventResult
	result.SuspiciousCount = eventResult.FailedLogons +
		len(eventResult.SuspiciousPowerShell) +
		len(eventResult.SuspiciousProcesses)

	if eventResult.FailedLogons > 50 {
		result.Status = "threats_found"
		result.ThreatCount = eventResult.FailedLogons
	} else if result.SuspiciousCount > 0 {
		result.Status = "suspicious"
	}

	result.ScanDuration = int(time.Since(start).Seconds())
	return result, nil
}

// runPowerShell executes a PowerShell script and returns output
func runPowerShell(script string) (string, error) {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}
