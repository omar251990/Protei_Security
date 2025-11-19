package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/protei/security-suite/pkg/auth"
	"github.com/protei/security-suite/pkg/config"
	"github.com/protei/security-suite/pkg/database"
	"github.com/protei/security-suite/pkg/logger"
	"github.com/protei/security-suite/pkg/models"
)

// LoginRequest represents login credentials
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// LoginResponse represents login response
type LoginResponse struct {
	Token     string       `json:"token"`
	ExpiresAt time.Time    `json:"expires_at"`
	User      UserResponse `json:"user"`
}

// UserResponse represents user info in responses
type UserResponse struct {
	ID       uuid.UUID `json:"id"`
	Username string    `json:"username"`
	Email    string    `json:"email"`
	FullName string    `json:"full_name"`
	RoleName string    `json:"role_name"`
	IsActive bool      `json:"is_active"`
}

// Login handles user authentication
// @Summary User login
// @Description Authenticate user and return JWT token
// @Tags auth
// @Accept json
// @Produce json
// @Param credentials body LoginRequest true "Login credentials"
// @Success 200 {object} LoginResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Router /api/v1/auth/login [post]
func Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Invalid request"})
		return
	}

	// Find user
	var user models.User
	if err := database.DB.Preload("Role").Where("username = ?", req.Username).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "Invalid credentials"})
		return
	}

	// Check if account is locked
	if user.LockedUntil != nil && user.LockedUntil.After(time.Now()) {
		c.JSON(http.StatusUnauthorized, ErrorResponse{
			Error: "Account is locked. Please try again later.",
		})
		return
	}

	// Verify password
	if !auth.CheckPasswordHash(req.Password, user.PasswordHash) {
		// Increment failed login attempts
		user.FailedLoginAttempts++
		cfg := config.Get()

		if user.FailedLoginAttempts >= cfg.Security.MaxLoginAttempts {
			lockUntil := time.Now().Add(time.Duration(cfg.Security.LockoutDuration) * time.Second)
			user.LockedUntil = &lockUntil
		}

		database.DB.Save(&user)

		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "Invalid credentials"})
		return
	}

	// Check if user is active
	if !user.IsActive {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: "Account is disabled"})
		return
	}

	// Reset failed attempts and update last login
	user.FailedLoginAttempts = 0
	user.LockedUntil = nil
	now := time.Now()
	user.LastLoginAt = &now
	database.DB.Save(&user)

	// Generate JWT token
	cfg := config.Get()
	token, err := auth.GenerateToken(
		user.ID,
		user.Username,
		user.RoleID,
		cfg.Security.JWTSecret,
		cfg.Security.JWTExpirationHours,
	)

	if err != nil {
		logger.Log.Errorf("Failed to generate token: %v", err)
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "Failed to generate token"})
		return
	}

	expiresAt := time.Now().Add(time.Duration(cfg.Security.JWTExpirationHours) * time.Hour)

	c.JSON(http.StatusOK, LoginResponse{
		Token:     token,
		ExpiresAt: expiresAt,
		User: UserResponse{
			ID:       user.ID,
			Username: user.Username,
			Email:    user.Email,
			FullName: user.FullName,
			RoleName: user.Role.Name,
			IsActive: user.IsActive,
		},
	})
}

// GetAssets retrieves all assets
// @Summary List assets
// @Description Get list of all assets
// @Tags assets
// @Produce json
// @Security BearerAuth
// @Param page query int false "Page number" default(1)
// @Param limit query int false "Items per page" default(50)
// @Param asset_type query string false "Filter by asset type"
// @Param os_type query string false "Filter by OS type"
// @Success 200 {object} PaginatedResponse
// @Failure 401 {object} ErrorResponse
// @Router /api/v1/assets [get]
func GetAssets(c *gin.Context) {
	page := c.DefaultQuery("page", "1")
	limit := c.DefaultQuery("limit", "50")
	assetType := c.Query("asset_type")
	osType := c.Query("os_type")

	var assets []models.Asset
	query := database.DB.Preload("Agent")

	// Apply filters
	if assetType != "" {
		query = query.Where("asset_type = ?", assetType)
	}
	if osType != "" {
		query = query.Where("os_type = ?", osType)
	}

	// Get total count
	var total int64
	query.Model(&models.Asset{}).Count(&total)

	// Apply pagination
	var pageInt, limitInt int
	if _, err := fmt.Sscanf(page, "%d", &pageInt); err != nil {
		pageInt = 1
	}
	if _, err := fmt.Sscanf(limit, "%d", &limitInt); err != nil {
		limitInt = 50
	}

	offset := (pageInt - 1) * limitInt
	query.Offset(offset).Limit(limitInt).Find(&assets)

	c.JSON(http.StatusOK, PaginatedResponse{
		Data:       assets,
		Total:      int(total),
		Page:       pageInt,
		Limit:      limitInt,
		TotalPages: (int(total) + limitInt - 1) / limitInt,
	})
}

// GetAssetByID retrieves a single asset
// @Summary Get asset by ID
// @Description Get detailed information about a specific asset
// @Tags assets
// @Produce json
// @Security BearerAuth
// @Param id path string true "Asset ID"
// @Success 200 {object} models.Asset
// @Failure 404 {object} ErrorResponse
// @Router /api/v1/assets/{id} [get]
func GetAssetByID(c *gin.Context) {
	id := c.Param("id")

	assetID, err := uuid.Parse(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Invalid asset ID"})
		return
	}

	var asset models.Asset
	if err := database.DB.Preload("Agent").First(&asset, assetID).Error; err != nil {
		c.JSON(http.StatusNotFound, ErrorResponse{Error: "Asset not found"})
		return
	}

	c.JSON(http.StatusOK, asset)
}

// GetVulnerabilities retrieves vulnerabilities
// @Summary List vulnerabilities
// @Description Get list of vulnerabilities with filters
// @Tags vulnerabilities
// @Produce json
// @Security BearerAuth
// @Param severity query string false "Filter by severity"
// @Param status query string false "Filter by status"
// @Param asset_id query string false "Filter by asset ID"
// @Success 200 {object} PaginatedResponse
// @Router /api/v1/vulnerabilities [get]
func GetVulnerabilities(c *gin.Context) {
	severity := c.Query("severity")
	status := c.Query("status")
	assetID := c.Query("asset_id")

	var vulnerabilities []models.Vulnerability
	query := database.DB.Preload("Asset")

	if severity != "" {
		query = query.Where("severity = ?", severity)
	}
	if status != "" {
		query = query.Where("status = ?", status)
	}
	if assetID != "" {
		query = query.Where("asset_id = ?", assetID)
	}

	// Get total count
	var total int64
	query.Model(&models.Vulnerability{}).Count(&total)

	query.Order("cvss_score DESC").Limit(100).Find(&vulnerabilities)

	c.JSON(http.StatusOK, PaginatedResponse{
		Data:  vulnerabilities,
		Total: int(total),
	})
}

// GetDashboardStats returns dashboard statistics
// @Summary Dashboard statistics
// @Description Get overview statistics for the dashboard
// @Tags dashboard
// @Produce json
// @Security BearerAuth
// @Success 200 {object} DashboardStats
// @Router /api/v1/dashboard/stats [get]
func GetDashboardStats(c *gin.Context) {
	var stats DashboardStats

	// Count assets
	database.DB.Model(&models.Asset{}).Where("status = ?", "active").Count(&stats.TotalAssets)

	// Count vulnerabilities by severity
	database.DB.Model(&models.Vulnerability{}).Where("status IN ?", []string{"open", "acknowledged"}).Count(&stats.TotalVulnerabilities)
	database.DB.Model(&models.Vulnerability{}).Where("severity = ? AND status IN ?", "CRITICAL", []string{"open", "acknowledged"}).Count(&stats.CriticalVulnerabilities)
	database.DB.Model(&models.Vulnerability{}).Where("severity = ? AND status IN ?", "HIGH", []string{"open", "acknowledged"}).Count(&stats.HighVulnerabilities)

	// Count agents
	database.DB.Model(&models.Agent{}).Where("status = ?", "active").Count(&stats.ActiveAgents)

	// Recent scans
	database.DB.Model(&models.ScanExecution{}).Where("created_at > ?", time.Now().Add(-24*time.Hour)).Count(&stats.RecentScans)

	// Recent events
	database.DB.Model(&models.Event{}).Where("severity IN ? AND created_at > ?", []string{"CRITICAL", "HIGH"}, time.Now().Add(-24*time.Hour)).Count(&stats.RecentHighSeverityEvents)

	c.JSON(http.StatusOK, stats)
}

// Response types
type ErrorResponse struct {
	Error string `json:"error"`
}

type PaginatedResponse struct {
	Data       interface{} `json:"data"`
	Total      int         `json:"total"`
	Page       int         `json:"page,omitempty"`
	Limit      int         `json:"limit,omitempty"`
	TotalPages int         `json:"total_pages,omitempty"`
}

type DashboardStats struct {
	TotalAssets               int64 `json:"total_assets"`
	TotalVulnerabilities      int64 `json:"total_vulnerabilities"`
	CriticalVulnerabilities   int64 `json:"critical_vulnerabilities"`
	HighVulnerabilities       int64 `json:"high_vulnerabilities"`
	ActiveAgents              int64 `json:"active_agents"`
	RecentScans               int64 `json:"recent_scans"`
	RecentHighSeverityEvents  int64 `json:"recent_high_severity_events"`
}
