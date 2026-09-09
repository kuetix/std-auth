package transitions

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/kuetix/engine/engine/domain"
	"github.com/kuetix/engine/engine/domain/interfaces"
	"github.com/kuetix/engine/engine/workflow"
	"github.com/redis/go-redis/v9"
)

// BFF (Backend-For-Frontend) session support: an alternative to handing a
// browser the raw JWT (see jwt.go's GenerateToken/ValidateToken, still the
// right choice for a non-browser client like a native mobile app, which
// keeps sending "Authorization: Bearer <token>" untouched). Instead, the
// browser only ever holds an opaque, random session id - the real JWT
// (and the claims that came with it) lives server-side in Redis, keyed by
// that id. Two things this buys over a JWT sitting in even an httpOnly
// cookie:
//   - Instant revocation: DEL the Redis key (see ClearSession) ends the
//     session immediately. A bare JWT stays valid until its own expiry no
//     matter what the server does afterwards - there's no way to
//     invalidate one early without a separate blocklist, which is exactly
//     what this Redis-backed store amounts to.
//   - The token's claims are never observable client-side at all, not
//     even by decoding a cookie value (a JWT is signed, not encrypted -
//     anyone can base64-decode one and read its payload even though they
//     can't forge a new one from it).
//
// ResolveSession below is a drop-in replacement for the
// ExtractTokenFromHeader -> ValidateToken two-state chain most protected
// workflows already use: same response shape (userId/username/email/
// token - see ValidateToken above), so swapping to it doesn't require
// touching anything downstream that reads $validated.userId etc. It also
// still honors a Bearer Authorization header first, falling back to the
// opaque session cookie only when there's none - a mobile client, or a
// browser session issued before a project adopted this module, keeps
// working unchanged.
const bffSessionKeyPrefix = "bff:session:"

// bffUserSessionsPrefix keys a per-user ZSET (member = session id, score =
// last-seen unix seconds) so a user's active sessions can be listed and
// revoked individually without a keyspace SCAN. CreateSession adds to it,
// ClearSession and the session-management transitions remove from it, and
// every read self-heals by dropping ids whose record has expired. See
// zmist's zmist/session package + workflows/user/sessions*.wsl.
const bffUserSessionsPrefix = "bff:user:sessions:"

type bffTransitions struct {
	workflow.BaseServiceTransition
	db                *redis.Client
	sessionCookieName string
	csrfCookieName    string
	cookieDomain      string
}

// Cookie names default to "bff_session"/"bff_csrf" but are overridable via
// env (BFF_SESSION_COOKIE_NAME/BFF_CSRF_COOKIE_NAME) - a project already
// running its own differently-named session cookie (e.g. one issued
// before it adopted this module) can point these at its existing names so
// switching doesn't silently log out every currently-logged-in browser.
//
// cookieDomain (BFF_COOKIE_DOMAIN, default "" - host-only, the right
// choice whenever the frontend and this API are actually the same
// origin) matters specifically for the CSRF cookie: it's deliberately
// not httpOnly so the frontend's JS can read it back out of
// document.cookie and echo it as the X-CSRF-Token header (see
// VerifyCsrf), but document.cookie only ever exposes cookies whose
// Domain covers the CURRENT page's own host - not httpOnly-ness, Domain.
// A cookie set host-only by api.example.com is simply invisible to
// document.cookie on a page served from app.example.com, even though
// both share the same site - the browser still sends it correctly on
// requests TO api.example.com (that part needs no Domain override, and
// applies here too - see CreateSession), but the frontend can never read
// it back to satisfy the double-submit check, and every mutating request
// fails "missing X-CSRF-Token header" no matter how correctly everything
// else is wired. A deployment where the API lives on a different
// subdomain than the frontend it serves (e.g. api.example.com /
// app.example.com) needs this set to the shared parent domain
// ("example.com") so both cookies - session included, so ClearSession's
// clearing Set-Cookie matches what was actually set - are visible across
// both subdomains.
func NewBFFTransitions() interfaces.ServiceTransitions {
	dbNum, _ := strconv.Atoi(os.Getenv("REDIS_DB"))
	client := redis.NewClient(&redis.Options{
		Addr:     envOrBFF("REDIS_ADDR", "127.0.0.1:6379"),
		Password: os.Getenv("REDIS_PASSWORD"),
		DB:       dbNum,
	})
	return &bffTransitions{
		db:                client,
		sessionCookieName: envOrBFF("BFF_SESSION_COOKIE_NAME", "bff_session"),
		csrfCookieName:    envOrBFF("BFF_CSRF_COOKIE_NAME", "bff_csrf"),
		cookieDomain:      os.Getenv("BFF_COOKIE_DOMAIN"),
	}
}

func envOrBFF(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

type bffSessionRecord struct {
	UserID    string `json:"userId"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	Token     string `json:"token"`
	IssuedAt  string `json:"issuedAt"`
	ExpiresAt string `json:"expiresAt"`
	// Client metadata for the "your active sessions" list. Populated from
	// the login request; all optional (a session created before this was
	// added, or by a caller that passes "" , simply has blanks).
	IP        string `json:"ip,omitempty"`
	UserAgent string `json:"userAgent,omitempty"`
	Platform  string `json:"platform,omitempty"` // "web" | "ios" | "android" | "api"
}

// derivePlatform is a coarse best-effort classification of a session's
// origin from its User-Agent, for display in the session list only.
func derivePlatform(userAgent string) string {
	u := strings.ToLower(strings.TrimSpace(userAgent))
	switch {
	case u == "":
		return "api"
	case strings.Contains(u, "zmist-ios"), strings.Contains(u, "cfnetwork"), strings.Contains(u, "darwin"):
		return "ios"
	case strings.Contains(u, "zmist-android"), strings.Contains(u, "android"), strings.Contains(u, "okhttp"):
		return "android"
	case strings.Contains(u, "mozilla"), strings.Contains(u, "webkit"), strings.Contains(u, "gecko"):
		return "web"
	default:
		return "api"
	}
}

// firstForwardedIP takes the left-most address from an X-Forwarded-For
// list (the original client; the rest are proxies).
func firstForwardedIP(xff string) string {
	if i := strings.IndexByte(xff, ','); i != -1 {
		return strings.TrimSpace(xff[:i])
	}
	return strings.TrimSpace(xff)
}

// touchSession bumps a session's last-seen score in the per-user index so
// the session list can show "last active". Best-effort - a failure here
// must never break request auth.
func (t *bffTransitions) touchSession(ctx context.Context, userID, sessionID string) {
	if userID == "" || sessionID == "" {
		return
	}
	t.db.ZAdd(ctx, bffUserSessionsPrefix+userID, redis.Z{
		Score:  float64(time.Now().Unix()),
		Member: sessionID,
	})
}

func stringField(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

// CreateSession stores tokenResult (the whole map GenerateToken above
// returns - accepted as interface{} and type-asserted internally here,
// not destructured by the caller via a dotted-path argument) under a
// fresh random session id in Redis with a TTL of maxAgeSeconds, then sets
// that id - never the real token - as an httpOnly cookie, plus a second,
// deliberately JS-readable CSRF cookie for the double-submit check
// VerifyCsrf performs on mutating requests. interface{} rather than a
// concrete struct for both response and tokenResult for the same reason
// zmist's own (now-superseded-by-this) session.SetSessionCookies
// documented: this engine's action-argument binding doesn't reliably
// resolve a dotted path like $token.token, only the whole $token alias,
// and $http.response's binding as a raw interface value hasn't been
// proven the same way plain data types have.
func (t *bffTransitions) CreateSession(response interface{}, tokenResult interface{}, maxAgeSeconds int, clientIP string, userAgent string) (r domain.FlowStepResult) {
	w, ok := response.(http.ResponseWriter)
	if !ok {
		r.Success = false
		r.Error = fmt.Errorf("CreateSession: expected http.ResponseWriter in context, got %T", response)
		return
	}

	tokenMap, ok := tokenResult.(map[string]interface{})
	if !ok {
		r.Success = false
		r.Error = fmt.Errorf("CreateSession: expected a token result map, got %T", tokenResult)
		return
	}
	token := stringField(tokenMap, "token")
	if token == "" {
		r.Success = false
		r.Error = fmt.Errorf("CreateSession: token result had no non-empty \"token\" field")
		return
	}

	ip := firstForwardedIP(clientIP)
	record := bffSessionRecord{
		UserID:    stringField(tokenMap, "userId"),
		Username:  stringField(tokenMap, "username"),
		Email:     stringField(tokenMap, "email"),
		Token:     token,
		IssuedAt:  time.Now().UTC().Format(time.RFC3339),
		ExpiresAt: stringField(tokenMap, "expiresAt"),
		IP:        ip,
		UserAgent: strings.TrimSpace(userAgent),
		Platform:  derivePlatform(userAgent),
	}
	payload, err := json.Marshal(record)
	if err != nil {
		r.Success = false
		r.Error = fmt.Errorf("CreateSession: %w", err)
		return
	}

	sessionID, err := randomBFFToken()
	if err != nil {
		r.Success = false
		r.Error = fmt.Errorf("CreateSession: %w", err)
		return
	}
	csrfToken, err := randomBFFToken()
	if err != nil {
		r.Success = false
		r.Error = fmt.Errorf("CreateSession: %w", err)
		return
	}

	ctx := context.Background()
	if err := t.db.Set(ctx, bffSessionKeyPrefix+sessionID, payload, time.Duration(maxAgeSeconds)*time.Second).Err(); err != nil {
		r.Success = false
		r.Error = fmt.Errorf("CreateSession: %w", err)
		return
	}
	if record.UserID != "" {
		idx := bffUserSessionsPrefix + record.UserID
		t.db.ZAdd(ctx, idx, redis.Z{Score: float64(time.Now().Unix()), Member: sessionID})
		// Keep the index from outliving the longest-lived session record.
		t.db.Expire(ctx, idx, time.Duration(maxAgeSeconds)*time.Second)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     t.sessionCookieName,
		Value:    sessionID,
		Domain:   t.cookieDomain,
		Path:     "/",
		MaxAge:   maxAgeSeconds,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:   t.csrfCookieName,
		Value:  csrfToken,
		Domain: t.cookieDomain,
		Path:   "/",
		MaxAge: maxAgeSeconds,
		// Deliberately NOT HttpOnly - see VerifyCsrf's comment: the whole
		// double-submit scheme depends on JS being able to read this one
		// and echo it back as a header, unlike the session cookie above -
		// which is also exactly why cookieDomain (see this file's
		// NewBFFTransitions doc comment) matters so much for THIS cookie
		// specifically when the frontend and this API are on different
		// subdomains.
		HttpOnly: false,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	// Return the whole token result PLUS sessionId, so a login workflow can
	// respond with this alias directly: browsers ignore the body's
	// sessionId (they use the cookie), a native client stores it and sends
	// it as its Bearer token. Callers that only want the id still read
	// r.Response["sessionId"].
	out := make(map[string]interface{}, len(tokenMap)+1)
	for k, v := range tokenMap {
		out[k] = v
	}
	out["sessionId"] = sessionID
	r.Success = true
	r.StatusCode = http.StatusOK
	r.Response = out
	return
}

// sessionResponse is the shared success shape - identical to what
// validateJWT returns, plus "sessionId" so a caller (e.g. a session-list
// endpoint) can tell which of the listed sessions is the current one.
func sessionResponse(sessionID string, record bffSessionRecord) map[string]interface{} {
	return map[string]interface{}{
		"token": Token{
			Raw:       record.Token,
			UserID:    record.UserID,
			Username:  record.Username,
			Email:     record.Email,
			IssuedAt:  record.IssuedAt,
			ExpiresAt: record.ExpiresAt,
		},
		"userId":    record.UserID,
		"username":  record.Username,
		"email":     record.Email,
		"issuedAt":  record.IssuedAt,
		"expiresAt": record.ExpiresAt,
		"sessionId": sessionID,
	}
}

// loadSessionRecord fetches and decodes bff:session:<sessionID>.
func (t *bffTransitions) loadSessionRecord(ctx context.Context, sessionID string) (bffSessionRecord, bool) {
	raw, err := t.db.Get(ctx, bffSessionKeyPrefix+sessionID).Result()
	if err != nil {
		return bffSessionRecord{}, false
	}
	var record bffSessionRecord
	if err := json.Unmarshal([]byte(raw), &record); err != nil {
		return bffSessionRecord{}, false
	}
	return record, true
}

// ResolveSession is the read-side counterpart to CreateSession. A Bearer
// Authorization header is tried first: its value is looked up as an opaque
// session id (a native client now stores the id CreateSession returns and
// sends it as the Bearer token, so mobile sessions are revocable and show
// up in the session list too), and only if that misses is it validated as
// a raw JWT - keeping older mobile builds, and any pure-JWT integration,
// working unchanged (those simply can't be revoked before their own
// expiry). With no usable Authorization header it falls back to the opaque
// session cookie.
func (t *bffTransitions) ResolveSession(authHeader, cookieHeader string) (r domain.FlowStepResult) {
	ctx := context.Background()

	if len(authHeader) > len(bearerPrefix) && authHeader[:len(bearerPrefix)] == bearerPrefix {
		token := authHeader[len(bearerPrefix):]
		if token != "" {
			if record, ok := t.loadSessionRecord(ctx, token); ok {
				t.touchSession(ctx, record.UserID, token)
				r.Success = true
				r.StatusCode = http.StatusOK
				r.Response = sessionResponse(token, record)
				return
			}
			// Not a live session id - treat it as a raw JWT (legacy /
			// non-browser). No sessionId in the response for this path.
			return validateJWT(token)
		}
	}

	sessionID := readBFFCookie(cookieHeader, t.sessionCookieName)
	if sessionID == "" {
		r.Success = false
		r.Error = fmt.Errorf("no session token in Authorization header or %s cookie", t.sessionCookieName)
		return
	}

	record, ok := t.loadSessionRecord(ctx, sessionID)
	if !ok {
		r.Success = false
		r.Error = fmt.Errorf("session not found or expired")
		return
	}
	t.touchSession(ctx, record.UserID, sessionID)

	r.Success = true
	r.StatusCode = http.StatusOK
	r.Response = sessionResponse(sessionID, record)
	return
}

// VerifyCsrf implements the double-submit cookie check for mutating
// routes: the CSRF cookie is deliberately not httpOnly, specifically so a
// same-origin page can read document.cookie and echo its value back as a
// header - a cross-site request can make the browser attach the session
// cookie automatically, but can't read or resend this one, so the
// header/cookie pair won't match.
func (t *bffTransitions) VerifyCsrf(csrfHeader, cookieHeader string) (r domain.FlowStepResult) {
	if csrfHeader == "" {
		r.Success = false
		r.Error = fmt.Errorf("missing X-CSRF-Token header")
		return
	}
	cookieValue := readBFFCookie(cookieHeader, t.csrfCookieName)
	if cookieValue == "" || cookieValue != csrfHeader {
		r.Success = false
		r.Error = fmt.Errorf("CSRF token mismatch")
		return
	}
	r.Success = true
	return
}

// ClearSession is logout - unlike a bare JWT (valid until its own expiry
// no matter what), the session actually stops working the instant this
// runs, since ResolveSession's Redis lookup will simply find nothing
// afterwards.
func (t *bffTransitions) ClearSession(response interface{}, cookieHeader string, authHeader string) (r domain.FlowStepResult) {
	w, ok := response.(http.ResponseWriter)
	if !ok {
		r.Success = false
		r.Error = fmt.Errorf("ClearSession: expected http.ResponseWriter in context, got %T", response)
		return
	}

	ctx := context.Background()
	// The session id is in the cookie (browser) or is itself the Bearer
	// value (a native client since it started sending the opaque id).
	sessionID := readBFFCookie(cookieHeader, t.sessionCookieName)
	if sessionID == "" && len(authHeader) > len(bearerPrefix) && authHeader[:len(bearerPrefix)] == bearerPrefix {
		sessionID = authHeader[len(bearerPrefix):]
	}
	if sessionID != "" {
		record, _ := t.loadSessionRecord(ctx, sessionID)
		if err := t.db.Del(ctx, bffSessionKeyPrefix+sessionID).Err(); err != nil {
			// Not fatal - the cookies still get cleared below, so the
			// browser stops sending this session id either way; a
			// transient Redis error here just leaves the now-orphaned
			// Redis entry to expire on its own TTL instead of being
			// removed immediately.
			fmt.Printf("ClearSession: failed to delete session %s: %s\n", sessionID, err)
		}
		if record.UserID != "" {
			t.db.ZRem(ctx, bffUserSessionsPrefix+record.UserID, sessionID)
		}
	}

	for _, name := range []string{t.sessionCookieName, t.csrfCookieName} {
		http.SetCookie(w, &http.Cookie{
			Name:   name,
			Value:  "",
			Domain: t.cookieDomain,
			// Domain must match what CreateSession actually set exactly -
			// a browser treats a differently-scoped Set-Cookie as a
			// different cookie entirely, so this wouldn't clear anything
			// if it drifted from CreateSession's value.
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: name == t.sessionCookieName,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		})
	}

	r.Success = true
	return
}

func readBFFCookie(cookieHeader, name string) string {
	if cookieHeader == "" {
		return ""
	}
	cookies, err := http.ParseCookie(cookieHeader)
	if err != nil {
		return ""
	}
	for _, c := range cookies {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

func randomBFFToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generating random token: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
