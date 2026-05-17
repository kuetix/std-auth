package transitions

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kuetix/engine/engine/domain"
	"github.com/kuetix/engine/engine/domain/interfaces"
	"github.com/kuetix/engine/engine/workflow"
	"github.com/kuetix/logger"
)

type jwtTransitions struct {
	workflow.BaseServiceTransition
}

func NewJWTTransitions() interfaces.ServiceTransitions {
	return &jwtTransitions{}
}

// JWTClaims represents the claims in a JWT token
type JWTClaims struct {
	UserID   string `json:"userId"`
	Username string `json:"username"`
	Email    string `json:"email"`
	jwt.RegisteredClaims
}

type Token struct {
	UserID    string `json:"userId"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	Raw       string `json:"raw"`
	IssuedAt  string `json:"issuedAt"`
	ExpiresAt string `json:"expiresAt"`
	jwt.RegisteredClaims
}

var (
	jwtSecretOnce  sync.Once
	jwtSecretValue string
)

// getJWTSecret returns the JWT secret.
//
// Resolution order:
//  1. JWT_SECRET environment variable (required in production).
//  2. APP_ENV=development (or JWT_ALLOW_DEV_SECRET=1): generate a random
//     per-process secret. Tokens minted with it become invalid on restart.
//
// In any other case, the process aborts. A hardcoded fallback would let an
// attacker who reads this source forge tokens for every deployment that
// forgot to set JWT_SECRET.
func getJWTSecret() string {
	jwtSecretOnce.Do(func() {
		if secret := os.Getenv("JWT_SECRET"); secret != "" {
			jwtSecretValue = secret
			return
		}

		dev := os.Getenv("APP_ENV") == "development" ||
			os.Getenv("JWT_ALLOW_DEV_SECRET") == "1"
		if !dev {
			logger.Fatalf("JWT_SECRET environment variable is required (set APP_ENV=development or JWT_ALLOW_DEV_SECRET=1 to auto-generate an ephemeral dev secret)")
		}

		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err != nil {
			logger.Fatalf("failed to generate ephemeral JWT secret: %v", err)
		}
		jwtSecretValue = hex.EncodeToString(buf)
		logger.Warn("JWT_SECRET unset — generated an ephemeral random secret for this process; tokens will not survive a restart")
	})
	return jwtSecretValue
}

// GenerateToken generates a JWT token for a user
func (j *jwtTransitions) GenerateToken(userID, username, email string, expiresInHours int) (r domain.FlowStepResult) {
	if expiresInHours <= 0 {
		expiresInHours = 24 // Default to 24 hours
	}

	claims := JWTClaims{
		UserID:   userID,
		Username: username,
		Email:    email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * time.Duration(expiresInHours))),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "kuetix-api",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(getJWTSecret()))
	if err != nil {
		r.Success = false
		r.Error = fmt.Errorf("failed to generate token: %w", err)
		return
	}

	r.Success = true
	r.Response = map[string]interface{}{
		"token":     tokenString,
		"expiresAt": claims.ExpiresAt.Time.Format(time.RFC3339),
		"userId":    userID,
		"username":  username,
		"email":     email,
	}
	return
}

// ValidateToken validates a JWT token and returns the claims
func (j *jwtTransitions) ValidateToken(tokenString string) (r domain.FlowStepResult) {
	if tokenString == "" {
		r.Success = false
		r.Error = fmt.Errorf("token is required")
		return
	}

	// Parse and validate token
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(getJWTSecret()), nil
	})

	if err != nil {
		r.Success = false
		r.Error = fmt.Errorf("invalid token: %w", err)
		return
	}

	// Extract claims
	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		r.Success = false
		r.Error = fmt.Errorf("invalid token claims")
		return
	}

	r.Success = true
	r.Response = map[string]interface{}{
		"token": Token{
			Raw:       tokenString,
			UserID:    claims.UserID,
			Username:  claims.Username,
			Email:     claims.Email,
			IssuedAt:  claims.IssuedAt.Time.Format(time.RFC3339),
			ExpiresAt: claims.ExpiresAt.Time.Format(time.RFC3339),
		},
		"userId":    claims.UserID,
		"username":  claims.Username,
		"email":     claims.Email,
		"issuedAt":  claims.IssuedAt.Time.Format(time.RFC3339),
		"expiresAt": claims.ExpiresAt.Time.Format(time.RFC3339),
	}
	return
}

// RefreshToken generates a new token from an existing valid token
func (j *jwtTransitions) RefreshToken(tokenString string, expiresInHours int) (r domain.FlowStepResult) {
	// First validate the existing token
	validateResult := j.ValidateToken(tokenString)
	if !validateResult.Success {
		r.Success = false
		r.Error = validateResult.Error
		return
	}

	// Extract user info from validated token
	userInfo, ok := validateResult.Response.(map[string]interface{})
	if !ok {
		r.Success = false
		r.Error = fmt.Errorf("invalid token validation response: expected map[string]interface{}")
		return
	}
	userID, _ := userInfo["userId"].(string)
	username, _ := userInfo["username"].(string)
	email, _ := userInfo["email"].(string)
	if userID == "" {
		r.Success = false
		r.Error = fmt.Errorf("validated token is missing required claim: userId")
		return
	}

	// Generate new token
	return j.GenerateToken(userID, username, email, expiresInHours)
}

// ExtractTokenFromHeader extracts the JWT token from Authorization header
func (j *jwtTransitions) ExtractTokenFromHeader(authHeader string) (r domain.FlowStepResult) {
	if authHeader == "" {
		r.Success = false
		r.Error = fmt.Errorf("authorization header is missing")
		return
	}

	// Expected format: "Bearer <token>"
	const bearerPrefix = "Bearer "
	if len(authHeader) < len(bearerPrefix) {
		r.Success = false
		r.Error = fmt.Errorf("invalid authorization header format")
		return
	}

	if authHeader[:len(bearerPrefix)] != bearerPrefix {
		r.Success = false
		r.Error = fmt.Errorf("authorization header must start with 'Bearer '")
		return
	}

	token := authHeader[len(bearerPrefix):]
	if token == "" {
		r.Success = false
		r.Error = fmt.Errorf("token is empty")
		return
	}

	r.Success = true
	r.Response = map[string]interface{}{
		"token": token,
	}
	return
}

// GetToken validates the token extracted from the Authorization header
func (j *jwtTransitions) GetToken(authHeader string) (r domain.FlowStepResult) {
	r = j.ExtractTokenFromHeader(authHeader)
	if !r.Success {
		return
	}

	token := r.Response.(map[string]interface{})["token"].(string)
	validateToken := j.ValidateToken(token)
	if !validateToken.Success {
		r.Success = false
		r.Error = validateToken.Error
		r.Response = nil
		return
	}

	r.Response = validateToken.Response.(map[string]interface{})["token"].(Token)
	r.Success = true
	return
}
