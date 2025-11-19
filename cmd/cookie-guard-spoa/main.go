// Cookie Guard SPOE for HAProxy (Negasus library).
//
// Endpoints (metrics listener):
//   - /healthz  : liveness probe -> "ok"
//   - /metrics  : Prometheus metrics
//
// Metrics exposed:
//   - cookie_guard_issue_total
//   - cookie_guard_verify_total
//   - cookie_guard_verify_outcome_total{outcome="valid"|"invalid"}
//   - cookie_guard_handler_seconds_bucket|sum|count{message="issue-token"|"verify-token"}
//   - cookie_guard_build_info{version="<ldflags-set>"}
//
// Build (embed version):
//
//	go build -trimpath -ldflags "-s -w -X 'main.version=$(git describe --tags --always || echo dev)'" -o bin/cookie-guard-spoa ./cmd/cookie-guard-spoa
//
// Run (dev):
//
//	./bin/cookie-guard-spoa -listen 127.0.0.1:9903 -metrics 127.0.0.1:9904 -secret /etc/cookie-guard/secret.key -ttl 1h
//
// Token details:
//
//	token = base64url(payload) + "." + base64url(HMAC_SHA256(secret, payload))
//	payload = ip|ua_sha1|iat|exp|nonce
package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/negasus/haproxy-spoe-go/action"
	"github.com/negasus/haproxy-spoe-go/agent"
	"github.com/negasus/haproxy-spoe-go/logger"
	"github.com/negasus/haproxy-spoe-go/request"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	altcha "github.com/altcha-org/altcha-lib-go"
)

// Version is set at build time with -ldflags "-X 'main.version=...'"
var version = "dev"

// CLI flags
var (
	listenAddr  = flag.String("listen", "127.0.0.1:9903", "SPOE listen address")
	metricsAddr = flag.String("metrics", "127.0.0.1:9904", "Metrics/health listen address (empty to disable)")
	secretPath  = flag.String("secret", "/etc/cookie-guard-spoa/secret.key", "Primary secret file path")
	ttl         = flag.Duration("ttl", 1*time.Hour, "Token TTL (e.g., 1h)")
	skew        = flag.Duration("skew", 30*time.Second, "Clock skew allowance")
	debugMode   = flag.Bool("debug", false, "Enable verbose debug logging (for development only)")

	// ALTCHA endpoints (served on the metrics listener)
	altchaEnable     = flag.Bool("altcha", true, "Enable ALTCHA endpoints on the metrics listener")
	altchaExpires    = flag.Duration("altcha-expires", 2*time.Minute, "ALTCHA challenge expiration window")
	cookieSecureFlag = flag.Bool("cookie-secure", false, "Set Secure on hb_v2 cookies issued by ALTCHA verify handler")
	altchaAssetsDir  = flag.String("altcha-assets", "/etc/haproxy/assets/altcha", "ALTCHA assets directory (serves /assets/altcha/* from here)")
	altchaPagePath   = flag.String("altcha-page", "/etc/haproxy/altcha_challenge.html.lf", "ALTCHA challenge HTML page to serve at /altcha")

	// BotD ingestion
	botdEnable    = flag.Bool("botd", true, "Enable BotD report ingestion endpoint")
	botdTTL       = flag.Duration("botd-ttl", 5*time.Minute, "BotD verdict retention window")
	botdCacheMax  = flag.Int("botd-cache-max", 100000, "Maximum BotD cache entries (0 disables storage)")
	botdAssetsDir = flag.String("botd-assets", "/etc/haproxy/assets/botd", "BotD assets directory (serves /assets/botd/* from here)")

	// Bind behavior
	uaBind = flag.Bool("ua-bind", true, "Bind tokens to User-Agent; set false to ignore UA when issuing and verifying")
)

// Secret storage (atomic swap on SIGHUP)
type secrets struct{ primary []byte }

var sec atomic.Pointer[secrets]

// ---------------- Prometheus metrics ----------------

var (
	mIssueTotal  = prometheus.NewCounter(prometheus.CounterOpts{Name: "cookie_guard_issue_total", Help: "Total number of issued challenge tokens"})
	mVerifyTotal = prometheus.NewCounter(prometheus.CounterOpts{Name: "cookie_guard_verify_total", Help: "Total number of verify requests"})

	mVerifyOutcome = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cookie_guard_verify_outcome_total",
			Help: "Verify outcomes by result",
		},
		[]string{"outcome"},
	)

	mHandlerSeconds = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "cookie_guard_handler_seconds",
			Help:    "Time spent handling SPOE messages",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"message"},
	)

	mBuildInfo = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "cookie_guard_build_info",
			Help: "Build information",
		},
		[]string{"version"},
	)

	mBotdReports = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cookie_guard_botd_reports_total",
			Help: "Total number of BotD reports by verdict",
		},
		[]string{"verdict"},
	)

	mBotdCacheEntries = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "cookie_guard_botd_cache_entries",
			Help: "Number of active BotD verdicts stored in memory",
		},
	)

	mBotdCacheEvictions = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "cookie_guard_botd_cache_evictions_total",
			Help: "Number of BotD cache entries evicted due to expiration or capacity",
		},
	)
)

// ---------------- helpers ----------------

func loadSecret(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("secret path required")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	k := strings.TrimSpace(string(b))
	if k == "" {
		return nil, errors.New("empty secret")
	}
	return []byte(k), nil
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func b64urldec(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

func debugf(format string, args ...interface{}) {
	if debugMode == nil || !*debugMode {
		return
	}
	log.Printf("debug: "+format, args...)
}

func randNonce(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return b64url(buf), nil
}

func sha1hex(s string) string {
	h := sha1.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

func sign(secret []byte, payload string) []byte {
	h := hmac.New(sha256.New, secret)
	_, _ = io.WriteString(h, payload)
	return h.Sum(nil)
}

func abbr(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// Derive a distinct HMAC key for ALTCHA from the primary secret.
func altchaKeyFromSecret(secret []byte) []byte {
	h := hmac.New(sha256.New, secret)
	_, _ = io.WriteString(h, "altcha")
	return h.Sum(nil)
}

var nowUnix = func() int64 { return time.Now().Unix() }

const challengeLevelAltcha = "altcha"

// ---------------- BotD verdict cache ----------------

const (
	botdVerdictBad     = "bad"
	botdVerdictGood    = "good"
	botdVerdictSuspect = "suspect"
)

type botdVerdictEntry struct {
	Verdict    string
	BotKind    string
	Confidence float64
	RequestID  string
	Expires    time.Time
}

var (
	botdMu    sync.Mutex
	botdCache = make(map[string]botdVerdictEntry)
)

func clientIPFromRequest(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	h, _, _ := net.SplitHostPort(r.RemoteAddr)
	if h == "" {
		return r.RemoteAddr
	}
	return h
}

func normalizeBotdVerdict(v string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "bad":
		return botdVerdictBad, true
	case "good":
		return botdVerdictGood, true
	case "notdetected", "not_detected", "unknown", "suspect":
		return botdVerdictSuspect, true
	default:
		return "", false
	}
}

func botdKey(ip, uaHash string) string {
	return ip + "|" + uaHash
}

func pruneBotdLocked(now time.Time) {
	for k, entry := range botdCache {
		if now.After(entry.Expires) {
			delete(botdCache, k)
			mBotdCacheEvictions.Inc()
		}
	}
	mBotdCacheEntries.Set(float64(len(botdCache)))
}

func storeBotdVerdict(ip, uaHash string, entry botdVerdictEntry) {
	if ip == "" || uaHash == "" {
		return
	}
	if botdCacheMax != nil && *botdCacheMax == 0 {
		return
	}
	key := botdKey(ip, uaHash)
	if botdCache == nil {
		botdCache = make(map[string]botdVerdictEntry)
	}
	botdMu.Lock()
	defer botdMu.Unlock()

	now := time.Now()
	pruneBotdLocked(now)

	if botdCacheMax != nil && *botdCacheMax > 0 {
		for len(botdCache) >= *botdCacheMax {
			for k := range botdCache {
				delete(botdCache, k)
				mBotdCacheEvictions.Inc()
				break
			}
		}
	}

	botdCache[key] = entry
	mBotdCacheEntries.Set(float64(len(botdCache)))
	debugf("botd: cached verdict=%s bot_kind=%s ip=%s ua_hash=%s expires=%s", entry.Verdict, entry.BotKind, ip, uaHash, entry.Expires.Format(time.RFC3339))
}

func lookupBotdVerdict(ip, uaHash string) (botdVerdictEntry, bool) {
	if ip == "" || uaHash == "" || botdCache == nil {
		return botdVerdictEntry{}, false
	}
	key := botdKey(ip, uaHash)
	botdMu.Lock()
	defer botdMu.Unlock()

	now := time.Now()
	pruneBotdLocked(now)

	entry, ok := botdCache[key]
	if !ok {
		return botdVerdictEntry{}, false
	}
	if now.After(entry.Expires) {
		delete(botdCache, key)
		mBotdCacheEntries.Set(float64(len(botdCache)))
		mBotdCacheEvictions.Inc()
		return botdVerdictEntry{}, false
	}
	debugf("botd: cache hit verdict=%s bot_kind=%s ip=%s ua_hash=%s", entry.Verdict, entry.BotKind, ip, uaHash)
	return entry, true
}

func clampConfidence(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

// ---------------- token issue / verify ----------------

func issueToken(ip, ua string) (token string, maxAgeSec int, err error) {
	// Backwards-compatible helper: compute UA hash from string
	return issueTokenWithUAHash(ip, sha1hex(ua))
}

// issueTokenWithUAHash issues a token using a precomputed UA SHA-1 hex hash.
// If uaHash is empty and UA binding is disabled, the caller should pass sha1hex("").
func issueTokenWithUAHash(ip, uaHash string) (token string, maxAgeSec int, err error) {
	if ip == "" {
		debugf("issue-token: skipping token issue for empty src-ip (ua_hash len=%d)", len(uaHash))
		return "", 0, nil
	}
	uah := uaHash
	iat := nowUnix()
	exp := iat + int64(ttl.Seconds())
	nonce, err := randNonce(nonceByteLen)
	if err != nil {
		debugf("issue-token: failed to generate nonce: %v", err)
		return "", 0, err
	}
	payload := fmt.Sprintf("%s|%s|%d|%d|%s", ip, uah, iat, exp, nonce)

	s := sec.Load()
	if s == nil || len(s.primary) == 0 {
		debugf("issue-token: secret not loaded (payload ip=%s)", ip)
		return "", 0, errors.New("no secret loaded")
	}

	// HMAC over the *raw payload*
	sig := b64url(sign(s.primary, payload))

	tok := b64url([]byte(payload)) + "." + sig
	debugf("issue-token: ip=%s ua_sha1=%s iat=%d exp=%d nonce=%s payload=%q sig_b64=%s token_len=%d maxAge=%ds",
		ip, uah, iat, exp, nonce, payload, abbr(sig, 16), len(tok), int(*ttl/time.Second))

	return tok, int(*ttl / time.Second), nil
}

func verifyToken(ip, ua, token string, skewSec int64) bool {
	ok, _, _ := verifyTokenDetailed(ip, ua, token, skewSec)
	return ok
}

func verifyTokenDetailed(ip, ua, token string, skewSec int64) (bool, string, int64) {
	// Backwards-compatible path: compute UA hash and delegate
	return verifyTokenWithUAHash(ip, sha1hex(ua), token, skewSec)
}

// verifyTokenWithUAHash verifies using a precomputed UA SHA-1 hex hash.
func verifyTokenWithUAHash(ip, uaHash, token string, skewSec int64) (bool, string, int64) {
	if ip == "" || token == "" {
		return false, "empty src-ip or token", 0
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		debugf("verify-token: malformed token: missing '.' separator (len=%d)", len(token))
		return false, "token missing payload/signature separator", 0
	}

	// decode payload and signature
	rawPayload, err := b64urldec(parts[0])
	if err != nil {
		debugf("verify-token: payload base64 decode failed: %v", err)
		return false, "payload base64 decode failed", 0
	}
	gotSig, err := b64urldec(parts[1])
	if err != nil {
		debugf("verify-token: signature base64 decode failed: %v", err)
		return false, "signature base64 decode failed", 0
	}

	// parse payload
	payload := string(rawPayload) // ip|ua_sha1|iat|exp|nonce
	ps := strings.Split(payload, "|")
	if len(ps) != 5 {
		debugf("verify-token: unexpected payload field count: got=%d payload=%q", len(ps), string(rawPayload))
		return false, "unexpected payload field count", 0
	}
	tip, tuah, tiat, texp := ps[0], ps[1], ps[2], ps[3]
	if tip != ip || tuah != uaHash {
		debugf("verify-token: mismatch tip=%s ip=%s cookieUA=%s reqUAhash=%s", tip, ip, tuah, uaHash)
		return false, "ip or ua hash mismatch", 0
	}

	var iat, exp int64
	if _, err := fmt.Sscanf(tiat, "%d", &iat); err != nil {
		debugf("verify-token: invalid issued-at: %q err=%v", tiat, err)
		return false, "invalid issued-at", 0
	}
	if _, err := fmt.Sscanf(texp, "%d", &exp); err != nil {
		debugf("verify-token: invalid expiration: %q err=%v", texp, err)
		return false, "invalid expiration", 0
	}
	now := nowUnix()
	if now+skewSec < iat || now-skewSec > exp {
		debugf("verify-token: window invalid now=%d iat=%d exp=%d skew=%d", now, iat, exp, skewSec)
		return false, "token not within validity window", 0
	}

	s := sec.Load()
	if s == nil || len(s.primary) == 0 {
		return false, "secret not loaded", 0
	}

	// HMAC over the *raw payload* (same as issuer)
	wantSig := sign(s.primary, payload)

	if !hmac.Equal(wantSig, gotSig) {
		debugf("verify-token: signature mismatch (ip=%s) payload=%q", ip, payload)
		return false, "signature mismatch", 0
	}

	age := now - iat
	if age < 0 {
		age = 0
	}

	return true, "", age
}

func deriveSessionHMAC(token string) string {
	if token == "" {
		return ""
	}
	s := sec.Load()
	if s == nil || len(s.primary) == 0 {
		return ""
	}
	h := hmac.New(sha256.New, s.primary)
	_, _ = io.WriteString(h, "cookieguard-session|")
	_, _ = io.WriteString(h, token)
	return hex.EncodeToString(h.Sum(nil))
}

// ---------------- Negasus handler ----------------

// Input validation / guards
const maxTokenLen = 8192 // safe upper bound

var b64urlDotRe = regexp.MustCompile(`^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+$`)

const (
	nonceByteLen    = 12
	uaHashHexLen    = 40
	nonceStrLen     = (nonceByteLen*8 + 5) / 6
	signatureB64Len = (sha256.Size*8 + 5) / 6
)

func b64RawLen(n int) int {
	return (n*8 + 5) / 6
}

func digitsCount(n int64) int {
	if n < 0 {
		n = -n
	}
	return len(strconv.FormatInt(n, 10))
}

func tokenLooksPlausible(ip, token string) bool {
	dot := strings.IndexByte(token, '.')
	if dot <= 0 || dot >= len(token)-1 {
		return false
	}
	if len(token)-dot-1 != signatureB64Len {
		return false
	}

	payloadLen := dot

	now := nowUnix()
	skewSec := int64(skew.Seconds())
	if skewSec < 0 {
		skewSec = -skewSec
	}
	minIat := now - skewSec
	if minIat < 0 {
		minIat = 0
	}
	maxIat := now + skewSec

	ttlSec := int64(ttl.Seconds())
	if ttlSec < 0 {
		ttlSec = -ttlSec
	}
	minExp := minIat + ttlSec
	maxExp := maxIat + ttlSec

	minIatDigits := digitsCount(minIat)
	maxIatDigits := digitsCount(maxIat)
	minExpDigits := digitsCount(minExp)
	maxExpDigits := digitsCount(maxExp)

	for iDigits := minIatDigits; iDigits <= maxIatDigits; iDigits++ {
		for eDigits := minExpDigits; eDigits <= maxExpDigits; eDigits++ {
			payloadBytes := len(ip) + 1 + uaHashHexLen + 1 + iDigits + 1 + eDigits + 1 + nonceStrLen
			if payloadLen == b64RawLen(payloadBytes) {
				return true
			}
		}
	}
	return false
}

func setBotdVars(req *request.Request, entry botdVerdictEntry, ok bool) {
	scope := action.ScopeTransaction
	req.Actions.SetVar(scope, "botd_verdict", "")
	req.Actions.SetVar(scope, "botd_tool", "")
	req.Actions.SetVar(scope, "botd_kind", "")
	req.Actions.SetVar(scope, "botd_confidence", "")
	req.Actions.SetVar(scope, "botd_request_id", "")
	if !ok {
		return
	}
	req.Actions.SetVar(scope, "botd_verdict", entry.Verdict)
	req.Actions.SetVar(scope, "botd_tool", entry.BotKind) // legacy name for compatibility
	req.Actions.SetVar(scope, "botd_kind", entry.BotKind)
	req.Actions.SetVar(scope, "botd_confidence", fmt.Sprintf("%.3f", entry.Confidence))
	req.Actions.SetVar(scope, "botd_request_id", entry.RequestID)
}

func makeHandler() func(*request.Request) {
	return func(req *request.Request) {
		// "issue-token"
		if mes, err := req.Messages.GetByName("issue-token"); err == nil {
			tStart := time.Now()
			var ipStr, ua string
			var uaHash string
			if v, ok := mes.KV.Get("src-ip"); ok {
				switch t := v.(type) {
				case net.IP:
					ipStr = t.String()
				case string:
					ipStr = t
				}
			}
			if v, ok := mes.KV.Get("ua_sha1"); ok {
				if s, ok := v.(string); ok {
					uaHash = strings.ToLower(s)
				}
			} else if v, ok := mes.KV.Get("ua"); ok {
				if s, ok := v.(string); ok {
					ua = s
				}
			}
			if uaBind != nil && !*uaBind {
				uaHash = sha1hex("")
			} else if uaHash == "" {
				uaHash = sha1hex(ua)
			}

			entry, found := lookupBotdVerdict(ipStr, uaHash)
			setBotdVars(req, entry, found)
			tok, maxAge, err := issueTokenWithUAHash(ipStr, uaHash)
			if err == nil {
				req.Actions.SetVar(action.ScopeTransaction, "token", tok)
				req.Actions.SetVar(action.ScopeTransaction, "max_age", fmt.Sprintf("%d", maxAge))
				if tok != "" {
					mIssueTotal.Inc()
				}
			} else {
				req.Actions.SetVar(action.ScopeTransaction, "token", "")
				req.Actions.SetVar(action.ScopeTransaction, "max_age", "0")
			}
			mHandlerSeconds.WithLabelValues("issue-token").Observe(time.Since(tStart).Seconds())
		}

		// "verify-token"
		if mes, err := req.Messages.GetByName("verify-token"); err == nil {
			tStart := time.Now()
			mVerifyTotal.Inc()

			var ipStr, ua, cookie string
			var uaHash string
			if v, ok := mes.KV.Get("src-ip"); ok {
				switch t := v.(type) {
				case net.IP:
					ipStr = t.String()
				case string:
					ipStr = t
				}
			}
			if v, ok := mes.KV.Get("ua_sha1"); ok {
				if s, ok := v.(string); ok {
					uaHash = strings.ToLower(s)
				}
			} else if v, ok := mes.KV.Get("ua"); ok {
				if s, ok := v.(string); ok {
					ua = s
				}
			}
			if v, ok := mes.KV.Get("cookie"); ok {
				if s, ok := v.(string); ok {
					cookie = s
				}
			}

			ageSeconds := "0"
			sessionHMAC := ""
			challengeLevel := ""

			// Guards
			if cookie == "" || len(cookie) > maxTokenLen || !b64urlDotRe.MatchString(cookie) {
				req.Actions.SetVar(action.ScopeTransaction, "valid", "0")
				req.Actions.SetVar(action.ScopeTransaction, "age_seconds", ageSeconds)
				mVerifyOutcome.WithLabelValues("invalid").Inc()
				debugf("verify-token: guard rejected cookie (len=%d match=%t)", len(cookie), b64urlDotRe.MatchString(cookie))
				mHandlerSeconds.WithLabelValues("verify-token").Observe(time.Since(tStart).Seconds())
				return
			}
			if !tokenLooksPlausible(ipStr, cookie) {
				req.Actions.SetVar(action.ScopeTransaction, "valid", "0")
				req.Actions.SetVar(action.ScopeTransaction, "age_seconds", ageSeconds)
				mVerifyOutcome.WithLabelValues("invalid").Inc()
				debugf("verify-token: guard rejected cookie due to implausible layout (ipLen=%d len=%d)", len(ipStr), len(cookie))
				mHandlerSeconds.WithLabelValues("verify-token").Observe(time.Since(tStart).Seconds())
				return
			}

			// Full verification
			if uaBind != nil && !*uaBind {
				uaHash = sha1hex("")
			} else if uaHash == "" {
				uaHash = sha1hex(ua)
			}

			entry, found := lookupBotdVerdict(ipStr, uaHash)
			setBotdVars(req, entry, found)

			valid := "0"
			if ok, reason, age := verifyTokenWithUAHash(ipStr, uaHash, cookie, int64(skew.Seconds())); ok {
				valid = "1"
				ageSeconds = fmt.Sprintf("%d", age)
				sessionHMAC = deriveSessionHMAC(cookie)
				challengeLevel = challengeLevelAltcha
				mVerifyOutcome.WithLabelValues("valid").Inc()
				debugf("verify-token: accepted (ip=%s cookieLen=%d skew=%ds)", ipStr, len(cookie), int(skew.Seconds()))
			} else {
				mVerifyOutcome.WithLabelValues("invalid").Inc()
				debugf("verify-token: rejected (ip=%s cookieLen=%d reason=%s)", ipStr, len(cookie), reason)
			}
			req.Actions.SetVar(action.ScopeTransaction, "valid", valid)
			req.Actions.SetVar(action.ScopeTransaction, "age_seconds", ageSeconds)
			req.Actions.SetVar(action.ScopeTransaction, "session_hmac", sessionHMAC)
			req.Actions.SetVar(action.ScopeTransaction, "challenge_level", challengeLevel)
			mHandlerSeconds.WithLabelValues("verify-token").Observe(time.Since(tStart).Seconds())
		}
	}
}

// ---------------- main ----------------

func main() {
	flag.Parse()

	if *debugMode {
		log.Printf("debug logging enabled")
	}

	// Load secret
	b, err := loadSecret(*secretPath)
	if err != nil {
		log.Fatalf("failed loading secret: %v", err)
	}
	sec.Store(&secrets{primary: b})

	// Signals
	sigc := make(chan os.Signal, 2)
	signal.Notify(sigc, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for {
			switch <-sigc {
			case syscall.SIGHUP:
				nb, err := loadSecret(*secretPath)
				if err != nil {
					log.Printf("HUP reload failed: %v", err)
					continue
				}
				sec.Store(&secrets{primary: nb})
				log.Printf("secret reloaded")
			case syscall.SIGINT, syscall.SIGTERM:
				os.Exit(0)
			}
		}
	}()

	// Start SPOE agent
	ln, err := net.Listen("tcp4", *listenAddr)
	if err != nil {
		log.Fatalf("listen %s: %v", *listenAddr, err)
	}
	defer ln.Close()

	log.Printf("cookie-guard-spoa %s listening on %s (metrics: %s)", version, *listenAddr, *metricsAddr)

	h := makeHandler()
	a := agent.New(h, logger.NewDefaultLog())

	// Metrics server
	if *metricsAddr != "" {
		prometheus.MustRegister(mIssueTotal, mVerifyTotal, mVerifyOutcome, mHandlerSeconds, mBuildInfo, mBotdReports, mBotdCacheEntries, mBotdCacheEvictions)
		mBuildInfo.WithLabelValues(version).Set(1)

		go func() {
			mux := http.NewServeMux()
			mux.Handle("/metrics", promhttp.Handler())
			mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("ok\n"))
			})

			if *altchaEnable {
				ak := altchaKeyFromSecret(sec.Load().primary)

				mux.HandleFunc("/altcha-challenge", func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodGet {
						w.Header().Set("Allow", http.MethodGet)
						http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
						return
					}
					exp := time.Now().Add(*altchaExpires)
					opts := altcha.ChallengeOptions{
						HMACKey: string(ak),
						Expires: &exp,
					}
					ch, err := altcha.CreateChallenge(opts)
					if err != nil {
						debugf("altcha: create challenge failed: %v", err)
						http.Error(w, "challenge failed", http.StatusInternalServerError)
						return
					}
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(ch)
				})

				mux.HandleFunc("/altcha-verify", func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodPost {
						w.Header().Set("Allow", http.MethodPost)
						http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
						return
					}
					type verifyReq struct {
						Solution string `json:"solution"`
						Payload  string `json:"payload"`
						URL      string `json:"url"`
					}
					var vr verifyReq
					if err := json.NewDecoder(r.Body).Decode(&vr); err != nil {
						http.Error(w, "invalid json", http.StatusBadRequest)
						return
					}

					var payload map[string]any
					switch {
					case vr.Payload != "":
						// ALTCHA verifyurl sends base64 JSON as "payload"
						var data []byte
						if b, err := base64.StdEncoding.DecodeString(vr.Payload); err == nil {
							data = b
						} else if b, err := base64.RawStdEncoding.DecodeString(vr.Payload); err == nil {
							data = b
						} else {
							http.Error(w, "invalid payload base64", http.StatusBadRequest)
							return
						}
						if err := json.Unmarshal(data, &payload); err != nil {
							http.Error(w, "invalid payload json", http.StatusBadRequest)
							return
						}
					case vr.Solution != "":
						if len(vr.Solution) > 0 && vr.Solution[0] == '{' {
							if err := json.Unmarshal([]byte(vr.Solution), &payload); err != nil {
								http.Error(w, "invalid solution json", http.StatusBadRequest)
								return
							}
						} else {
							if b, err := base64.StdEncoding.DecodeString(vr.Solution); err == nil {
								_ = json.Unmarshal(b, &payload)
							} else if b, err2 := base64.RawStdEncoding.DecodeString(vr.Solution); err2 == nil {
								_ = json.Unmarshal(b, &payload)
							}
							if payload == nil {
								http.Error(w, "invalid solution base64", http.StatusBadRequest)
								return
							}
						}
					default:
						http.Error(w, "missing solution", http.StatusBadRequest)
						return
					}

					ok, err := altcha.VerifySolution(payload, string(ak), true)
					if err != nil || !ok {
						debugf("altcha: verify failed: %v", err)
						http.Error(w, "verification failed", http.StatusBadRequest)
						return
					}

					clientIP := func() string {
						if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
							parts := strings.Split(xff, ",")
							return strings.TrimSpace(parts[0])
						}
						h, _, _ := net.SplitHostPort(r.RemoteAddr)
						if h == "" {
							return r.RemoteAddr
						}
						return h
					}()
					ua := r.Header.Get("User-Agent")
					if uaBind != nil && !*uaBind {
						ua = ""
					}

					tok, maxAge, err := issueToken(clientIP, ua)
					if err != nil || tok == "" {
						debugf("altcha: token issue failed: %v", err)
						http.Error(w, "token issue failed", http.StatusInternalServerError)
						return
					}

					cookie := &http.Cookie{
						Name:     "hb_v2",
						Value:    tok,
						Path:     "/",
						MaxAge:   maxAge,
						Secure:   *cookieSecureFlag,
						HttpOnly: false,
						SameSite: http.SameSiteLaxMode,
					}
					http.SetCookie(w, cookie)
					debugf("altcha: issued hb_v2 (len=%d ip=%s)", len(tok), clientIP)

					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(`{"ok":true,"success":true}`))
				})

				// Serve the ALTCHA HTML page (from disk) at /altcha
				mux.HandleFunc("/altcha", func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodGet {
						w.Header().Set("Allow", http.MethodGet)
						http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
						return
					}
					p := *altchaPagePath
					f, err := os.Open(p)
					if err != nil {
						http.NotFound(w, r)
						return
					}
					defer f.Close()
					fi, _ := f.Stat()
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					w.Header().Set("Cache-Control", "no-store")
					http.ServeContent(w, r, filepath.Base(p), fi.ModTime(), f)
				})

				// Serve the local JS asset to avoid HAProxy's buffer limits.
				mux.HandleFunc("/assets/altcha/active/altcha.min.js", func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodGet {
						w.Header().Set("Allow", http.MethodGet)
						http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
						return
					}
					p := filepath.Join(*altchaAssetsDir, "active", "altcha.min.js")
					f, err := os.Open(p)
					if err != nil {
						http.NotFound(w, r)
						return
					}
					defer f.Close()
					fi, _ := f.Stat()
					w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
					w.Header().Set("Cache-Control", "public, max-age=604800")
					http.ServeContent(w, r, "altcha.min.js", fi.ModTime(), f)
				})
			}

			if *botdEnable {
				mux.HandleFunc("/assets/botd/active/botd.esm.js", func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodGet {
						w.Header().Set("Allow", http.MethodGet)
						http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
						return
					}
					p := filepath.Join(*botdAssetsDir, "active", "botd.esm.js")
					f, err := os.Open(p)
					if err != nil {
						http.NotFound(w, r)
						return
					}
					defer f.Close()
					fi, _ := f.Stat()
					w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
					w.Header().Set("Cache-Control", "public, max-age=604800")
					http.ServeContent(w, r, "botd.esm.js", fi.ModTime(), f)
				})

				mux.HandleFunc("/botd-report", func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodPost {
						w.Header().Set("Allow", http.MethodPost)
						http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
						return
					}
					defer r.Body.Close()
					var reqBody struct {
						Verdict    string  `json:"verdict"`
						BotKind    string  `json:"botKind"`
						Tool       string  `json:"tool"` // legacy
						Confidence float64 `json:"confidence"`
						RequestID  string  `json:"requestId"`
						UaHash     string  `json:"ua_hash"`
					}
					if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
						http.Error(w, "invalid json", http.StatusBadRequest)
						return
					}

					verdict, ok := normalizeBotdVerdict(reqBody.Verdict)
					if !ok {
						http.Error(w, "invalid verdict", http.StatusBadRequest)
						return
					}

					clientIP := clientIPFromRequest(r)
					if clientIP == "" {
						http.Error(w, "missing client ip", http.StatusBadRequest)
						return
					}

					ua := r.Header.Get("User-Agent")
					uaHash := strings.ToLower(strings.TrimSpace(reqBody.UaHash))
					if uaHash == "" {
						if uaBind != nil && !*uaBind {
							uaHash = sha1hex("")
						} else {
							uaHash = sha1hex(ua)
						}
					}
					if uaHash == "" {
						http.Error(w, "missing ua hash", http.StatusBadRequest)
						return
					}

					botKind := strings.TrimSpace(reqBody.BotKind)
					if botKind == "" {
						botKind = strings.TrimSpace(reqBody.Tool)
					}

					entry := botdVerdictEntry{
						Verdict:    verdict,
						BotKind:    botKind,
						Confidence: clampConfidence(reqBody.Confidence),
						RequestID:  strings.TrimSpace(reqBody.RequestID),
						Expires:    time.Now().Add(*botdTTL),
					}
					storeBotdVerdict(clientIP, uaHash, entry)
					mBotdReports.WithLabelValues(verdict).Inc()

					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(`{"ok":true}`))
				})
			}

			if err := http.ListenAndServe(*metricsAddr, mux); err != nil {
				log.Printf("metrics server error: %v", err)
			}
		}()
	}

	// Serve (blocking)
	if err := a.Serve(ln); err != nil {
		log.Fatalf("agent serve: %v", err)
	}

	<-context.Background().Done()
}
