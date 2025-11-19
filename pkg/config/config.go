package config

import (
	"fmt"
	"log"

	"github.com/spf13/viper"
)

// Config holds all application configuration
type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	Security SecurityConfig
	Scanner  ScannerConfig
	Agent    AgentConfig
}

type ServerConfig struct {
	Host         string
	Port         int
	TLSEnabled   bool
	TLSCertFile  string
	TLSKeyFile   string
	TrustedProxy []string
}

type DatabaseConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	DBName   string
	SSLMode  string
}

type SecurityConfig struct {
	JWTSecret           string
	JWTExpirationHours  int
	PasswordMinLength   int
	SessionTimeout      int
	MFARequired         bool
	MaxLoginAttempts    int
	LockoutDuration     int
}

type ScannerConfig struct {
	DefaultTimeout      int
	MaxConcurrentScans  int
	DefaultPorts        []string
	RateLimit           int
}

type AgentConfig struct {
	HeartbeatInterval   int
	MaxOfflineDuration  int
	TLSVerify           bool
	ClientCertRequired  bool
}

var AppConfig Config

// Load reads configuration from file and environment variables
func Load(configPath string) error {
	viper.SetConfigFile(configPath)
	viper.SetConfigType("yaml")

	// Set defaults
	setDefaults()

	// Read config file
	if err := viper.ReadInConfig(); err != nil {
		log.Printf("Warning: Could not read config file: %v", err)
	}

	// Override with environment variables
	viper.AutomaticEnv()

	// Unmarshal config
	if err := viper.Unmarshal(&AppConfig); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}

	log.Println("Configuration loaded successfully")
	return nil
}

func setDefaults() {
	// Server defaults
	viper.SetDefault("server.host", "0.0.0.0")
	viper.SetDefault("server.port", 8443)
	viper.SetDefault("server.tls_enabled", true)

	// Database defaults
	viper.SetDefault("database.host", "localhost")
	viper.SetDefault("database.port", 5432)
	viper.SetDefault("database.user", "protei")
	viper.SetDefault("database.dbname", "protei_security")
	viper.SetDefault("database.sslmode", "require")

	// Security defaults
	viper.SetDefault("security.jwt_expiration_hours", 24)
	viper.SetDefault("security.password_min_length", 12)
	viper.SetDefault("security.session_timeout", 3600)
	viper.SetDefault("security.mfa_required", false)
	viper.SetDefault("security.max_login_attempts", 5)
	viper.SetDefault("security.lockout_duration", 1800)

	// Scanner defaults
	viper.SetDefault("scanner.default_timeout", 300)
	viper.SetDefault("scanner.max_concurrent_scans", 5)
	viper.SetDefault("scanner.default_ports", []string{"1-1024", "3306", "5432", "8080", "8443"})
	viper.SetDefault("scanner.rate_limit", 1000)

	// Agent defaults
	viper.SetDefault("agent.heartbeat_interval", 60)
	viper.SetDefault("agent.max_offline_duration", 3600)
	viper.SetDefault("agent.tls_verify", true)
	viper.SetDefault("agent.client_cert_required", true)
}

// Get returns the loaded configuration
func Get() Config {
	return AppConfig
}
