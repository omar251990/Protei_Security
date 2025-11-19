package database

import (
	"fmt"
	"log"
	"time"

	"github.com/protei/security-suite/pkg/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB

// Config holds database configuration
type Config struct {
	Host     string
	Port     int
	User     string
	Password string
	DBName   string
	SSLMode  string
}

// Initialize connects to PostgreSQL and runs migrations
func Initialize(config Config) error {
	dsn := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		config.Host, config.Port, config.User, config.Password, config.DBName, config.SSLMode,
	)

	var err error
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
		NowFunc: func() time.Time {
			return time.Now().UTC()
		},
	})

	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	sqlDB, err := DB.DB()
	if err != nil {
		return fmt.Errorf("failed to get database instance: %w", err)
	}

	// Set connection pool settings
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(50)
	sqlDB.SetConnMaxLifetime(time.Hour)

	log.Println("Database connected successfully")

	// Run auto migrations
	return runMigrations()
}

// runMigrations auto-migrates all models
func runMigrations() error {
	log.Println("Running database migrations...")

	err := DB.AutoMigrate(
		&models.User{},
		&models.Role{},
		&models.Asset{},
		&models.Agent{},
		&models.ScanJob{},
		&models.ScanExecution{},
		&models.Vulnerability{},
		&models.Event{},
		&models.AgentScanResult{},
	)

	if err != nil {
		return fmt.Errorf("migration failed: %w", err)
	}

	log.Println("Migrations completed successfully")

	// Create default roles if they don't exist
	return createDefaultRoles()
}

// createDefaultRoles creates default system roles
func createDefaultRoles() error {
	log.Println("Creating default roles...")

	defaultRoles := []models.Role{
		{
			Name:        "admin",
			Description: "Full system access",
			Permissions: models.JSONB{"permissions": []string{"*"}},
		},
		{
			Name:        "security_analyst",
			Description: "Vulnerability management and scanning",
			Permissions: models.JSONB{
				"permissions": []string{
					"assets.read", "assets.write",
					"scans.read", "scans.write",
					"vulnerabilities.read",
					"reports.read",
				},
			},
		},
		{
			Name:        "auditor",
			Description: "Read-only access for compliance",
			Permissions: models.JSONB{
				"permissions": []string{
					"assets.read",
					"scans.read",
					"vulnerabilities.read",
					"reports.read",
					"events.read",
				},
			},
		},
		{
			Name:        "scanner_operator",
			Description: "Scan execution only",
			Permissions: models.JSONB{
				"permissions": []string{
					"scans.read", "scans.write",
					"assets.read",
				},
			},
		},
	}

	for _, role := range defaultRoles {
		var existingRole models.Role
		result := DB.Where("name = ?", role.Name).First(&existingRole)

		if result.Error == gorm.ErrRecordNotFound {
			if err := DB.Create(&role).Error; err != nil {
				return fmt.Errorf("failed to create role %s: %w", role.Name, err)
			}
			log.Printf("Created role: %s\n", role.Name)
		}
	}

	return nil
}

// GetDB returns the database instance
func GetDB() *gorm.DB {
	return DB
}
