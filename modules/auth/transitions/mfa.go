package transitions

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"time"

	"github.com/kuetix/engine/engine/domain"
	"github.com/kuetix/engine/engine/domain/interfaces"
	"github.com/kuetix/engine/engine/workflow"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
)

// Email 2FA (second-factor login) support. This is the server side of an
// opt-in flow: an account with security.twofactor = true (a flag the
// consuming project stores on its own user record - std-auth never reads
// it) can't complete a password login in one step any more. Instead:
//
//  1. The login workflow, after the password check passes, calls
//     IssueChallenge - which mints a short numeric code, stores only its
//     bcrypt hash in Redis under a fresh opaque challenge id with a short
//     TTL, and hands the plaintext code back for the workflow to email
//     (std-auth has no SMTP of its own - see the consuming project's own
//     email module). No session/JWT is issued at this point.
//  2. The user submits the code to a second endpoint, whose workflow
//     calls VerifyChallenge with the challenge id + code. On a match the
//     record is deleted and the caller's identity (userId/username/email,
//     same shape jwt.go's validateJWT returns) comes back so the workflow
//     can now issue the token/session exactly as a normal login would.
//
// Challenge state lives entirely in Redis here, keyed by the opaque
// challenge id, exactly like auth/bff.go's session store - same
// REDIS_ADDR/REDIS_PASSWORD/REDIS_DB config (via envOrBFF, shared with
// bff.go) and the same "the client only ever holds an opaque random id"
// property.
//
// VerifyChallenge/ResendChallenge deliberately never set r.Error for an
// expected outcome (wrong code, expired challenge, too many attempts) -
// they always r.Success = true with the outcome in r.Response, so the
// calling workflow branches on it with a plain assert and returns a clean
// 401. This engine treats any r.Error as fatal and bypasses the calling
// workflow's own `on fail ->` transition, dumping a raw internal trace to
// the client instead - the same convention the consuming project's email
// module documents at length. Only an actual Redis failure sets r.Error.
const mfaChallengeKeyPrefix = "mfa:challenge:"

// Defaults chosen to match common email-OTP practice: a 6-digit code is
// long enough that 5 guesses against it is a 1-in-200k shot, and the
// short TTL (passed per call by the workflow, typically 300s) closes the
// window regardless.
const (
	mfaDefaultCodeLength  = 6
	mfaDefaultMaxAttempts = 5
)

type mfaTransitions struct {
	workflow.BaseServiceTransition
	db *redis.Client
}

// NewMFATransitions builds the Redis-backed email-2FA challenge store.
// Mirrors NewBFFTransitions - same client options, same env vars, so a
// project already running auth/bff needs no extra configuration for this.
func NewMFATransitions() interfaces.ServiceTransitions {
	dbNum, _ := strconv.Atoi(os.Getenv("REDIS_DB"))
	client := redis.NewClient(&redis.Options{
		Addr:     envOrBFF("REDIS_ADDR", "127.0.0.1:6379"),
		Password: os.Getenv("REDIS_PASSWORD"),
		DB:       dbNum,
	})
	return &mfaTransitions{db: client}
}

func mfaCodeLength() int {
	if v, err := strconv.Atoi(os.Getenv("MFA_CODE_LENGTH")); err == nil && v >= 4 && v <= 10 {
		return v
	}
	return mfaDefaultCodeLength
}

func mfaMaxAttempts() int {
	if v, err := strconv.Atoi(os.Getenv("MFA_MAX_ATTEMPTS")); err == nil && v >= 1 {
		return v
	}
	return mfaDefaultMaxAttempts
}

// IsEnabled coerces a per-account "email 2FA on?" flag - however the
// consuming project's user record happens to represent it - to a plain
// bool the calling workflow can branch on with a bare assert. Accepts
// interface{} because the flag reaches this via a workflow expression
// like $user.value.security.twofactor: a real bool once the account has
// opted in, but nil for any account whose record predates the field (a
// nested-path lookup that hits nothing), and this engine won't bind a
// nil into a typed bool parameter without panicking. Also tolerates the
// string "true"/"1" in case the flag was ever round-tripped through a
// stringly-typed store.
func (t *mfaTransitions) IsEnabled(mfaFlag interface{}) (r domain.FlowStepResult) {
	enabled := false
	switch v := mfaFlag.(type) {
	case bool:
		enabled = v
	case string:
		enabled = v == "true" || v == "1"
	}
	r.Success = true
	r.StatusCode = 200
	r.Response = map[string]interface{}{"enabled": enabled}
	return
}

type mfaChallengeRecord struct {
	UserID   string `json:"userId"`
	Username string `json:"username"`
	Email    string `json:"email"`
	CodeHash string `json:"codeHash"`
	Attempts int    `json:"attempts"`
}

// generateNumericCode returns an n-digit decimal string (leading zeros
// preserved), each digit drawn from crypto/rand - not math/rand, which
// would make the code predictable from a couple of observed samples.
func generateNumericCode(n int) (string, error) {
	buf := make([]byte, n)
	for i := 0; i < n; i++ {
		d, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", fmt.Errorf("generating verification code: %w", err)
		}
		buf[i] = byte('0' + d.Int64())
	}
	return string(buf), nil
}

func hashMFACode(code string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("hashing verification code: %w", err)
	}
	return string(b), nil
}

// IssueChallenge mints a fresh 2FA challenge: a random numeric code, its
// bcrypt hash stored in Redis under a new opaque challenge id with a
// mfaTTLSeconds TTL, and the plaintext code handed back for the caller to
// email. mfaUserID/mfaUsername/mfaEmail are carried in the record so
// VerifyChallenge can return them later without the verify workflow
// re-looking-up the account.
func (t *mfaTransitions) IssueChallenge(mfaUserID, mfaUsername, mfaEmail string, mfaTTLSeconds int) (r domain.FlowStepResult) {
	if mfaUserID == "" {
		r.Success = false
		r.Error = fmt.Errorf("IssueChallenge: mfaUserID is required")
		return
	}
	if mfaTTLSeconds <= 0 {
		mfaTTLSeconds = 300
	}

	code, err := generateNumericCode(mfaCodeLength())
	if err != nil {
		r.Success = false
		r.Error = fmt.Errorf("IssueChallenge: %w", err)
		return
	}
	codeHash, err := hashMFACode(code)
	if err != nil {
		r.Success = false
		r.Error = fmt.Errorf("IssueChallenge: %w", err)
		return
	}
	challengeID, err := randomBFFToken()
	if err != nil {
		r.Success = false
		r.Error = fmt.Errorf("IssueChallenge: %w", err)
		return
	}

	payload, err := json.Marshal(mfaChallengeRecord{
		UserID:   mfaUserID,
		Username: mfaUsername,
		Email:    mfaEmail,
		CodeHash: codeHash,
		Attempts: 0,
	})
	if err != nil {
		r.Success = false
		r.Error = fmt.Errorf("IssueChallenge: %w", err)
		return
	}

	ctx := context.Background()
	if err := t.db.Set(ctx, mfaChallengeKeyPrefix+challengeID, payload, time.Duration(mfaTTLSeconds)*time.Second).Err(); err != nil {
		r.Success = false
		r.Error = fmt.Errorf("IssueChallenge: %w", err)
		return
	}

	r.Success = true
	r.StatusCode = 200
	r.Response = map[string]interface{}{
		"challengeId": challengeID,
		"code":        code,
	}
	return
}

// mfaInvalid is VerifyChallenge's shared "not valid" response shape: a
// machine-readable `reason` code plus a `message` a workflow can hand
// straight to an end user.
func mfaInvalid(reason, message string) map[string]interface{} {
	return map[string]interface{}{"valid": false, "reason": reason, "message": message}
}

// VerifyChallenge checks a submitted code against a pending challenge.
// Always r.Success = true unless Redis itself fails - the outcome is in
// r.Response (see this file's header comment).
//
// On an invalid attempt r.Response is {valid:false, reason, message}:
//   - reason "expired"           - no such challenge (unknown id or TTL lapsed)
//   - reason "too_many_attempts" - attempt cap hit; the challenge is deleted
//   - reason "incorrect"         - wrong code, attempts still left
//
// On valid, the record is deleted and {valid:true, userId, username,
// email} comes back (same keys jwt.go's validateJWT uses) for the verify
// workflow to issue the real token/session with.
func (t *mfaTransitions) VerifyChallenge(mfaChallengeId, mfaCode string) (r domain.FlowStepResult) {
	r.Success = true
	r.StatusCode = 200

	if mfaChallengeId == "" || mfaCode == "" {
		r.Response = mfaInvalid("expired", "That code is no longer valid. Request a new one.")
		return
	}

	ctx := context.Background()
	key := mfaChallengeKeyPrefix + mfaChallengeId

	raw, err := t.db.Get(ctx, key).Result()
	if err == redis.Nil {
		r.Response = mfaInvalid("expired", "That code is no longer valid. Request a new one.")
		return
	}
	if err != nil {
		r.Success = false
		r.Error = fmt.Errorf("VerifyChallenge: %w", err)
		return
	}

	var record mfaChallengeRecord
	if err := json.Unmarshal([]byte(raw), &record); err != nil {
		r.Success = false
		r.Error = fmt.Errorf("VerifyChallenge: %w", err)
		return
	}

	record.Attempts++
	if record.Attempts > mfaMaxAttempts() {
		// Burn the challenge - no more guesses against this code.
		t.db.Del(ctx, key)
		r.Response = mfaInvalid("too_many_attempts", "Too many incorrect attempts. Request a new code.")
		return
	}

	if bcrypt.CompareHashAndPassword([]byte(record.CodeHash), []byte(mfaCode)) != nil {
		// Persist the incremented attempt count without touching the TTL,
		// so the 5-minute window still closes on schedule.
		if payload, mErr := json.Marshal(record); mErr == nil {
			t.db.Set(ctx, key, payload, redis.KeepTTL)
		}
		r.Response = mfaInvalid("incorrect", "That code is incorrect.")
		return
	}

	// Correct code - single-use, so delete it before returning success.
	t.db.Del(ctx, key)
	r.Response = map[string]interface{}{
		"valid":    true,
		"userId":   record.UserID,
		"username": record.Username,
		"email":    record.Email,
	}
	return
}

// ResendChallenge rotates the code on an existing pending challenge (same
// challenge id, same remaining TTL) and resets its attempt counter,
// returning the new plaintext code + the address to send it to. A missing
// challenge is not an error - r.Response.found = false, and the resend
// workflow responds with the same generic message either way so a caller
// can't probe which challenge ids are live.
func (t *mfaTransitions) ResendChallenge(mfaChallengeId string) (r domain.FlowStepResult) {
	if mfaChallengeId == "" {
		r.Success = true
		r.StatusCode = 200
		r.Response = map[string]interface{}{"found": false}
		return
	}

	ctx := context.Background()
	key := mfaChallengeKeyPrefix + mfaChallengeId

	raw, err := t.db.Get(ctx, key).Result()
	if err == redis.Nil {
		r.Success = true
		r.StatusCode = 200
		r.Response = map[string]interface{}{"found": false}
		return
	}
	if err != nil {
		r.Success = false
		r.Error = fmt.Errorf("ResendChallenge: %w", err)
		return
	}

	var record mfaChallengeRecord
	if err := json.Unmarshal([]byte(raw), &record); err != nil {
		r.Success = false
		r.Error = fmt.Errorf("ResendChallenge: %w", err)
		return
	}

	code, err := generateNumericCode(mfaCodeLength())
	if err != nil {
		r.Success = false
		r.Error = fmt.Errorf("ResendChallenge: %w", err)
		return
	}
	codeHash, err := hashMFACode(code)
	if err != nil {
		r.Success = false
		r.Error = fmt.Errorf("ResendChallenge: %w", err)
		return
	}

	record.CodeHash = codeHash
	record.Attempts = 0
	payload, err := json.Marshal(record)
	if err != nil {
		r.Success = false
		r.Error = fmt.Errorf("ResendChallenge: %w", err)
		return
	}
	if err := t.db.Set(ctx, key, payload, redis.KeepTTL).Err(); err != nil {
		r.Success = false
		r.Error = fmt.Errorf("ResendChallenge: %w", err)
		return
	}

	r.Success = true
	r.StatusCode = 200
	r.Response = map[string]interface{}{
		"found": true,
		"code":  code,
		"email": record.Email,
	}
	return
}
