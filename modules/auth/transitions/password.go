package transitions

import (
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/kuetix/engine/engine/domain"
	"github.com/kuetix/engine/engine/domain/interfaces"
	"github.com/kuetix/engine/engine/workflow"
	"github.com/kuetix/uuid"
	"golang.org/x/crypto/bcrypt"
)

type userTransitions struct {
	workflow.BaseServiceTransition
}

func NewUserTransitions() interfaces.ServiceTransitions {
	return &userTransitions{}
}

// PasswordResetToken represents a password reset request
type PasswordResetToken struct {
	Email     string `json:"email"`
	Token     string `json:"token"`
	CreatedAt string `json:"createdAt"`
	ExpiresAt string `json:"expiresAt"`
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

// HashPassword creates a new user account with a hashed password
func (u *userTransitions) HashPassword(password string, min int) (r domain.FlowStepResult) {
	// Validate password strength (minimum 6 characters)
	if utf8.RuneCountInString(password) < min {
		r.Success = false
		r.Error = fmt.Errorf("password must be at least %d characters long", min)
		return
	}

	// Hash the password
	passwordHash, err := hashPassword(password)
	if err != nil {
		r.Success = false
		r.Error = fmt.Errorf("failed to hash password: %w", err)
		return
	}

	r.Success = true
	r.Response = passwordHash
	return
}

// ComparePassword verifies the provided password against the stored hash
func (u *userTransitions) ComparePassword(password, passwordHash string) (r domain.FlowStepResult) {
	// Verify password
	if err := checkPassword(password, passwordHash); err != nil {
		r.Success = false
		r.Error = fmt.Errorf("invalid email or password")
		return
	}

	r.Success = true
	r.Response = passwordHash
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

	// Hash the new password
	passwordHash, err := hashPassword(newPassword)
	if err != nil {
		r.Success = false
		r.Error = fmt.Errorf("failed to hash password: %w", err)
		return
	}

	r.Success = true
	r.Response = map[string]interface{}{
		"message":      "Password reset successfully",
		"passwordHash": passwordHash,
		"email":        email,
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

	// Generate a unique reset token
	resetToken := uuid.Id(email)
	now := time.Now()
	expiresAt := now.Add(24 * time.Hour) // Token expires in 24 hours

	// Create a reset token record
	resetTokenRecord := PasswordResetToken{
		Email:     email,
		Token:     resetToken,
		CreatedAt: now.Format(time.RFC3339),
		ExpiresAt: expiresAt.Format(time.RFC3339),
	}

	// In a real implementation, you would send an email here with the reset link
	// For now, we'll return the token in the response for testing purposes
	r.Success = true
	r.Response = map[string]interface{}{
		"message":    "If an account with that email exists, a password reset link has been sent",
		"email":      email,
		"token":      resetToken, // In production, this would be sent via email, not in the response
		"resetToken": resetTokenRecord,
		"expiresAt":  expiresAt.Format(time.RFC3339),
	}

	return
}
