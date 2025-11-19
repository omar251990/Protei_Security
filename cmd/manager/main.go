package main

import (
	"fmt"
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/protei/security-suite/internal/middleware"
	"github.com/protei/security-suite/pkg/api"
	"github.com/protei/security-suite/pkg/config"
	"github.com/protei/security-suite/pkg/database"
	"github.com/protei/security-suite/pkg/logger"
)

// @title Protei Security Suite API
// @version 1.0
// @description Enterprise security platform API
// @termsOfService http://swagger.io/terms/

// @contact.name API Support
// @contact.email support@protei-security.com

// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html

// @host localhost:8443
// @BasePath /api/v1
// @schemes https

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and JWT token

func main() {
	// Load configuration
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = "configs/manager.yaml"
	}

	if err := config.Load(configPath); err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	cfg := config.Get()

	// Initialize logger
	logger.Initialize("info")
	logger.Log.Info("Starting Protei Security Suite - Central Manager")

	// Initialize database
	dbConfig := database.Config{
		Host:     cfg.Database.Host,
		Port:     cfg.Database.Port,
		User:     cfg.Database.User,
		Password: cfg.Database.Password,
		DBName:   cfg.Database.DBName,
		SSLMode:  cfg.Database.SSLMode,
	}

	if err := database.Initialize(dbConfig); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	// Set Gin mode
	gin.SetMode(gin.ReleaseMode)

	// Create router
	router := gin.Default()

	// Apply middleware
	router.Use(middleware.CORSMiddleware())
	router.Use(gin.Recovery())

	// Health check endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status": "healthy",
			"service": "protei-manager",
		})
	})

	// API v1 routes
	v1 := router.Group("/api/v1")
	{
		// Public routes (no auth required)
		auth := v1.Group("/auth")
		{
			auth.POST("/login", api.Login)
		}

		// Protected routes (auth required)
		protected := v1.Group("")
		protected.Use(middleware.AuthMiddleware())
		{
			// Dashboard
			protected.GET("/dashboard/stats", api.GetDashboardStats)

			// Assets
			assets := protected.Group("/assets")
			{
				assets.GET("", api.GetAssets)
				assets.GET("/:id", api.GetAssetByID)
				// Additional asset endpoints can be added here
			}

			// Vulnerabilities
			vulns := protected.Group("/vulnerabilities")
			{
				vulns.GET("", api.GetVulnerabilities)
				// Additional vulnerability endpoints can be added here
			}

			// Scans
			scans := protected.Group("/scans")
			{
				// Scan endpoints will be added here
			}

			// Agents
			agents := protected.Group("/agents")
			{
				// Agent management endpoints will be added here
			}

			// Events
			events := protected.Group("/events")
			{
				// Event endpoints will be added here
			}

			// Reports
			reports := protected.Group("/reports")
			{
				// Report endpoints will be added here
			}
		}
	}

	// Start server
	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	logger.Log.Infof("Server listening on %s", addr)

	if cfg.Server.TLSEnabled {
		if err := router.RunTLS(addr, cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile); err != nil {
			log.Fatalf("Failed to start HTTPS server: %v", err)
		}
	} else {
		if err := router.Run(addr); err != nil {
			log.Fatalf("Failed to start HTTP server: %v", err)
		}
	}
}
