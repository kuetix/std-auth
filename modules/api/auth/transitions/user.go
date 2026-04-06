package transitions

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
	"unicode/utf8"

	jsonDbCache "github.com/anare/filejsondb"

	"github.com/kuetix/engine/pkg/domain"
	"github.com/kuetix/engine/pkg/domain/interfaces"
	"github.com/kuetix/engine/pkg/workflow"
	"github.com/kuetix/uuid"
	"golang.org/x/crypto/bcrypt"
)

type userTransitions struct {
	workflow.BaseServiceTransition
	dbm   *jsonDbCache.DB
	db    *jsonDbCache.Collection
	index *jsonDbCache.Collection
}

func NewUserTransitions() interfaces.ServiceTransitions {
	return &userTransitions{}
}

//goland:noinspection GoUnusedConst
const (
	UserTypeSimple          = "simple"
	UserTypeSaml            = "saml"
	UserTypeSso             = "sso"
	UserTypeOauth           = "oauth"
	UserTypeLdap            = "ldap"
	UserTypeActiveDirectory = "active_directory"
	UserTypeApiKey          = "api_key"
	UserTypeMagicLink       = "magic_link"
	UserTypeSocial          = "social"
	UserTypeFacebook        = "facebook"
	UserTypeGoogle          = "google"
	UserTypeApple           = "apple"
	UserTypeGithub          = "github"
	UserTypePlain           = "plain"
	UserTypeUnknown         = "unknown"
	UserTypeCustom          = "custom"
)

// User represents a user account in the system
type User struct {
	ID           string `json:"id"`
	Email        string `json:"email"`
	PasswordHash string `json:"passwordHash"`
	Locked       bool   `json:"locked"`
	Type         string `json:"type"`
	CreatedAt    string `json:"createdAt"`
	UpdatedAt    string `json:"updatedAt"`
}

// Index represents a user index for quick lookups by email (or other identifiers)
type Index struct {
	ID        string `json:"id"`
	UserID    string `json:"userId"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
}

// PasswordResetToken represents a password reset request
type PasswordResetToken struct {
	Email     string `json:"email"`
	Token     string `json:"token"`
	CreatedAt string `json:"createdAt"`
	ExpiresAt string `json:"expiresAt"`
}

// getDB initializes and returns the database connection
func (u *userTransitions) getDB() (*jsonDbCache.Collection, error) {
	if u.db != nil {
		return u.db, nil
	}

	options := u.Ctx.Engine.GetApplication().Env.Options
	dbPath := options.Context["dbPath"].(string)

	// Default path if not provided
	if dbPath == "" {
		dbPath = "./runtime/data"
	}

	// Ensure directory exists
	if err := os.MkdirAll(dbPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}

	dbFile := filepath.Join(dbPath, "users")
	db, err := jsonDbCache.NewDB(dbFile)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}

	u.dbm = db
	u.db = u.dbm.NewCollection("users")
	u.index = u.dbm.NewCollection("index")
	return u.db, nil
}

// hashPassword creates a bcrypt hash of the password
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// checkPassword compares a password with its hash
func checkPassword(password, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

// Register creates a new user account with email and password
func (u *userTransitions) Register(email, password string) (r domain.FlowStepResult) {
	// Validate password strength (minimum 6 characters)
	if utf8.RuneCountInString(password) < 6 {
		r.Success = false
		r.Error = fmt.Errorf("password must be at least 6 characters long")
		return
	}

	// Get database connection
	db, err := u.getDB()
	if err != nil {
		r.Success = false
		r.Error = err
		return
	}

	// Check if a user already exists
	userID := uuid.Id(email)
	if db.Exists(userID) {
		r.Success = false
		r.Error = fmt.Errorf("user with email %s already exists", email)
		return
	}

	// Hash the password
	passwordHash, err := hashPassword(password)
	if err != nil {
		r.Success = false
		r.Error = fmt.Errorf("failed to hash password: %w", err)
		return
	}

	// Generate user ID
	now := time.Now().Format(time.RFC3339)

	// Create a new user
	user := User{
		ID:           userID,
		Email:        email,
		PasswordHash: passwordHash,
		Locked:       false,
		Type:         UserTypeSimple,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	// Save a user to a database with email as a key for easy lookup
	if err = db.Set(userID, user, "username"); err != nil {
		r.Success = false
		r.Error = fmt.Errorf("failed to save user: %w", err)
		return
	}

	r.Success = true
	r.Response = map[string]interface{}{
		"userId":    userID,
		"email":     email,
		"createdAt": now,
		"message":   "User registered successfully",
	}

	return
}

// UpdateIndex updates the user index with email and other identifier (e.g., for SSO users) to allow quick lookups
func (u *userTransitions) UpdateIndex(email, otherId string) (r domain.FlowStepResult) {
	// Get database connection
	_, err := u.getDB()
	if err != nil {
		r.Success = false
		r.Error = err
		return
	}

	idb := u.index

	now := time.Now().Format(time.RFC3339)

	// Check if a user already exists
	emailHash := uuid.Id(email)
	otherIdHash := uuid.Id(otherId)

	index := Index{
		ID:        emailHash,
		UserID:    otherIdHash,
		CreatedAt: now,
		UpdatedAt: now,
	}
	found := false
	userHash := emailHash
	if idb.Exists(userHash) {
		found = true
	} else {
		userHash = otherIdHash
		if idb.Exists(userHash) {
			found = true
		}
	}

	if found {
		err = idb.Get(userHash, &index)
		if err == nil {
			index.UpdatedAt = now
			index.UserID = userHash
		}
	}

	// Save a user to a database with email as a key for easy lookup
	if err = idb.Set(userHash, index); err != nil {
		r.Success = false
		r.Error = fmt.Errorf("failed to save user: %w", err)
		return
	}

	r.Success = true
	r.Response = map[string]interface{}{
		"id":        index.ID,
		"userId":    index.UserID,
		"createdAt": index.CreatedAt,
		"updatedAt": index.UpdatedAt,
		"message":   "Index updated successfully",
	}

	return
}

// LookupID looks up a user ID by email or other identifier using the index for quick retrieval
func (u *userTransitions) LookupID(key, email string) (r domain.FlowStepResult) {
	// Get database connection
	db, err := u.getDB()
	if err != nil {
		r.Success = false
		r.Error = err
		return
	}

	idb := u.index
	keyHash := uuid.Id(key)
	emailHash := uuid.Id(email)
	index := Index{}
	if err = idb.Get(keyHash, &index); err != nil {
		if err = idb.Get(emailHash, &index); err != nil {
			if !db.Exists(emailHash) {
				r.Success = false
				r.Error = fmt.Errorf("invalid email or password")
				return
			}
			index.ID = emailHash
		}
	}

	r.Success = true
	r.Response = map[string]interface{}{
		"id":        index.ID,
		"userId":    index.UserID,
		"createdAt": index.CreatedAt,
		"updatedAt": index.UpdatedAt,
	}
	return
}

// Login validates user credentials and returns user information
func (u *userTransitions) Login(login, password string) (r domain.FlowStepResult) {
	// Get database connection
	db, err := u.getDB()
	if err != nil {
		r.Success = false
		r.Error = err
		return
	}

	// Look up the user by email
	// login := uuid.Id(email)
	var user User
	if err = db.Get(login, &user); err != nil {
		login = uuid.Id(login)
		if err = db.Get(login, &user); err != nil {
			r.Success = false
			r.Error = fmt.Errorf("invalid email or password")
			return
		}
	}

	// Verify password
	if err = checkPassword(password, user.PasswordHash); err != nil {
		r.Success = false
		r.Error = fmt.Errorf("invalid email or password")
		return
	}

	r.Success = true
	r.Response = map[string]interface{}{
		"userId": user.ID,
		"email":  user.Email,
	}

	return
}

// GetUserByEmail retrieves a user by their email address
func (u *userTransitions) GetUserByEmail(email string) (r domain.FlowStepResult) {
	// Validate input
	if email == "" {
		r.Success = false
		r.Error = fmt.Errorf("email is required")
		return
	}

	// Get database connection
	db, err := u.getDB()
	if err != nil {
		r.Success = false
		r.Error = err
		return
	}

	// Look up user by email
	emailKey := uuid.Id(email)
	var user User
	if err := db.Get(emailKey, &user); err != nil {
		r.Success = false
		r.Error = fmt.Errorf("user not found")
		return
	}

	r.Success = true
	r.Response = map[string]interface{}{
		"userId":    user.ID,
		"email":     user.Email,
		"createdAt": user.CreatedAt,
		"updatedAt": user.UpdatedAt,
	}

	return
}

// GetAllUsers returns a list of all users (without password hashes)
func (u *userTransitions) GetAllUsers() (r domain.FlowStepResult) {
	// Get database connection
	db, err := u.getDB()
	if err != nil {
		r.Success = false
		r.Error = err
		return
	}

	// Get all users from database
	allData := db.GetAll()
	users := make([]map[string]interface{}, 0)

	for _, data := range allData {
		var user User
		if err := json.Unmarshal(data, &user); err != nil {
			continue
		}
		// Don't include password hash in response
		users = append(users, map[string]interface{}{
			"userId":    user.ID,
			"email":     user.Email,
			"createdAt": user.CreatedAt,
			"updatedAt": user.UpdatedAt,
		})
	}

	r.Success = true
	r.Response = map[string]interface{}{
		"users": users,
		"count": len(users),
	}

	return
}

// ResetPassword updates a user's password
func (u *userTransitions) ResetPassword(email, newPassword, requestingUserEmail string) (r domain.FlowStepResult) {
	// Validate inputs
	if email == "" {
		r.Success = false
		r.Error = fmt.Errorf("email is required")
		return
	}

	if newPassword == "" {
		r.Success = false
		r.Error = fmt.Errorf("new password is required")
		return
	}

	// Authorization check: users can only reset their own password
	if requestingUserEmail != email {
		r.Success = false
		r.Error = fmt.Errorf("you can only reset your own password")
		return
	}

	// Validate password strength (minimum 6 characters)
	if utf8.RuneCountInString(newPassword) < 6 {
		r.Success = false
		r.Error = fmt.Errorf("password must be at least 6 characters long")
		return
	}

	// Get database connection
	db, err := u.getDB()
	if err != nil {
		r.Success = false
		r.Error = err
		return
	}

	// Look up user by email
	emailKey := uuid.Id(email)
	var user User
	if err := db.Get(emailKey, &user); err != nil {
		r.Success = false
		r.Error = fmt.Errorf("user not found")
		return
	}

	// Hash the new password
	passwordHash, err := hashPassword(newPassword)
	if err != nil {
		r.Success = false
		r.Error = fmt.Errorf("failed to hash password: %w", err)
		return
	}

	// Update user password and timestamp
	user.PasswordHash = passwordHash
	user.UpdatedAt = time.Now().Format(time.RFC3339)

	// Save updated user to database
	if err := db.Set(emailKey, user); err != nil {
		r.Success = false
		r.Error = fmt.Errorf("failed to update password: %w", err)
		return
	}

	r.Success = true
	r.Response = map[string]interface{}{
		"message": "Password reset successfully",
		"email":   email,
	}

	return
}

// RequestPasswordReset initiates a password reset request by generating a reset token
func (u *userTransitions) RequestPasswordReset(email string) (r domain.FlowStepResult) {
	// Validate input
	if email == "" {
		r.Success = false
		r.Error = fmt.Errorf("email is required")
		return
	}

	// Get database connection
	db, err := u.getDB()
	if err != nil {
		r.Success = false
		r.Error = err
		return
	}

	// Check if user exists
	emailKey := uuid.Id(email)
	var user User
	if err := db.Get(emailKey, &user); err != nil {
		// For security reasons, don't reveal if the user exists or not
		// Return success regardless to prevent email enumeration
		r.Success = true
		r.Response = map[string]interface{}{
			"message": "If an account with that email exists, a password reset link has been sent",
			"email":   email,
		}
		return
	}

	// Generate a unique reset token
	resetToken := uuid.Id(email)
	now := time.Now()
	expiresAt := now.Add(24 * time.Hour) // Token expires in 24 hours

	// Create reset token record
	resetTokenRecord := PasswordResetToken{
		Email:     email,
		Token:     resetToken,
		CreatedAt: now.Format(time.RFC3339),
		ExpiresAt: expiresAt.Format(time.RFC3339),
	}

	// Store the reset token with a key based on the token itself
	// Key format: "reset_token_{uuid}" - this format should be used consistently
	// when retrieving the token for password reset verification
	tokenKey := fmt.Sprintf("reset_token_%s", resetToken)
	if err := db.Set(tokenKey, resetTokenRecord); err != nil {
		r.Success = false
		r.Error = fmt.Errorf("failed to create password reset token: %w", err)
		return
	}

	// In a real implementation, you would send an email here with the reset link
	// For now, we'll return the token in the response for testing purposes
	r.Success = true
	r.Response = map[string]interface{}{
		"message":   "If an account with that email exists, a password reset link has been sent",
		"email":     email,
		"token":     resetToken, // In production, this would be sent via email, not in the response
		"expiresAt": expiresAt.Format(time.RFC3339),
	}

	return
}
