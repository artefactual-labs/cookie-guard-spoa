// JS cookie challenge SPOA for HAProxy (Negasus library version).
// - Message "issue-token": sets txn.js.token and txn.js.max_age
// - Message "verify-token": sets txn.js.valid ("1"/"0")
//
// Token = base64url(payload) + "." + base64url(HMAC_SHA256(secret, payload))
// payload = ip|ua_sha1|iat|exp|nonce
//
// Build:  go build -trimpath -ldflags="-s -w" -o bin/js-spoa ./cmd/js-spoa
// Run:    ./bin/js-spoa -listen 127.0.0.1:9903 -metrics 127.0.0.1:9904 -secret /etc/js-spoa/secret.key -ttl 1h

package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/negasus/haproxy-spoe-go/action"
	"github.com/negasus/haproxy-spoe-go/agent"
	"github.com/negasus/haproxy-spoe-go/logger"
	"github.com/negasus/haproxy-spoe-go/request"
)

var (
	listenAddr  = flag.String("listen", "127.0.0.1:9903", "SPOE listen address")
	metricsAddr = flag.String("metrics", "127.0.0.1:9904", "Metrics/health listen address (empty to disable)")
	secretPath  = flag.String("secret", "/etc/js-spoa/secret.key", "Primary secret file path")
	ttl         = flag.Duration("ttl", 1*time.Hour, "Token TTL (e.g., 1h)")
	skew        = flag.Duration("skew", 30*time.Second, "Clock skew allowance")
)

type secrets struct{ primary []byte }

var sec atomic.Pointer[secrets]

// --- helpers ---

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
func b64urldec(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
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

func nowUnix() int64 { return time.Now().Unix() }

// --- token issue / verify ---

func issueToken(ip, ua string) (token string, maxAgeSec int, err error) {
	if ip == "" {
		return "", 0, nil
	}
	uah := sha1hex(ua)
	iat := nowUnix()
	exp := iat + int64(ttl.Seconds())
	nonce, err := randNonce(12)
	if err != nil {
		return "", 0, err
	}
	payload := fmt.Sprintf("%s|%s|%d|%d|%s", ip, uah, iat, exp, nonce)
	s := sec.Load()
	if s == nil || len(s.primary) == 0 {
		return "", 0, errors.New("no secret loaded")
	}
	sig := b64url(sign(s.primary, payload))
	return b64url([]byte(payload)) + "." + sig, int(*ttl / time.Second), nil
}

func verifyToken(ip, ua, token string, skewSec int64) bool {
	if ip == "" || token == "" {
		return false
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return false
	}
	raw, err := b64urldec(parts[0])
	if err != nil {
		return false
	}
	payload := string(raw) // ip|ua_sha1|iat|exp|nonce
	ps := strings.Split(payload, "|")
	if len(ps) != 5 {
		return false
	}
	tip, tuah, tiat, texp := ps[0], ps[1], ps[2], ps[3]
	if tip != ip || tuah != sha1hex(ua) {
		return false
	}
	var iat, exp int64
	if _, err := fmt.Sscanf(tiat, "%d", &iat); err != nil {
		return false
	}
	if _, err := fmt.Sscanf(texp, "%d", &exp); err != nil {
		return false
	}
	now := nowUnix()
	if now+skewSec < iat || now-skewSec > exp {
		return false
	}
	s := sec.Load()
	if s == nil || len(s.primary) == 0 {
		return false
	}
	want := sign(s.primary, parts[0])
	got, err := b64urldec(parts[1])
	if err != nil {
		return false
	}
	return hmac.Equal(want, got)
}

// --- Negasus handler ---

func makeHandler() func(*request.Request) {
	return func(req *request.Request) {
		// Handle "issue-token"
		if mes, err := req.Messages.GetByName("issue-token"); err == nil {
			var ipStr, ua string
			if v, ok := mes.KV.Get("src-ip"); ok {
				switch t := v.(type) {
				case net.IP:
					ipStr = t.String()
				case string:
					ipStr = t
				}
			}
			if v, ok := mes.KV.Get("ua"); ok {
				if s, ok := v.(string); ok {
					ua = s
				}
			}
			tok, maxAge, err := issueToken(ipStr, ua)
			if err == nil {
				req.Actions.SetVar(action.ScopeTransaction, "js.token", tok)
				req.Actions.SetVar(action.ScopeTransaction, "js.max_age", fmt.Sprintf("%d", maxAge))
			} else {
				// On error, set empty values; HAProxy will treat as "no token"
				req.Actions.SetVar(action.ScopeTransaction, "js.token", "")
				req.Actions.SetVar(action.ScopeTransaction, "js.max_age", "0")
			}
		}

		// Handle "verify-token"
		if mes, err := req.Messages.GetByName("verify-token"); err == nil {
			var ipStr, ua, cookie string
			if v, ok := mes.KV.Get("src-ip"); ok {
				switch t := v.(type) {
				case net.IP:
					ipStr = t.String()
				case string:
					ipStr = t
				}
			}
			if v, ok := mes.KV.Get("ua"); ok {
				if s, ok := v.(string); ok {
					ua = s
				}
			}
			if v, ok := mes.KV.Get("cookie"); ok {
				if s, ok := v.(string); ok {
					cookie = s
				}
			}
			valid := "0"
			if verifyToken(ipStr, ua, cookie, int64(skew.Seconds())) {
				valid = "1"
			}
			req.Actions.SetVar(action.ScopeTransaction, "js.valid", valid)
		}
	}
}

func main() {
	flag.Parse()

	// Load secret
	b, err := loadSecret(*secretPath)
	if err != nil {
		log.Fatalf("failed loading secret: %v", err)
	}
	sec.Store(&secrets{primary: b})

	// Handle signals (HUP to reload secret)
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

	// Start SPOE agent (Negasus style)
	ln, err := net.Listen("tcp4", *listenAddr)
	if err != nil {
		log.Fatalf("listen %s: %v", *listenAddr, err)
	}
	defer ln.Close()

	h := makeHandler()
	a := agent.New(h, logger.NewDefaultLog())

	// Optional metrics/health (plain HTTP on localhost)
	if *metricsAddr != "" {
		go func() {
			mux := http.NewServeMux()
			mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("ok\n"))
			})
			_ = http.ListenAndServe(*metricsAddr, mux)
		}()
	}

	// Serve
	if err := a.Serve(ln); err != nil {
		log.Fatalf("agent serve: %v", err)
	}

	// keep main alive (Serve is blocking; this is just for symmetry)
	<-context.Background().Done()
}

