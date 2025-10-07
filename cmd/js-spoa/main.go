// JS cookie challenge SPOE for HAProxy (Negasus library).
//
// Endpoints (metrics listener):
//   - /healthz  : liveness probe -> "ok"
//   - /metrics  : Prometheus metrics
//
// Metrics exposed:
//   - js_spoa_issue_total
//   - js_spoa_verify_total
//   - js_spoa_verify_outcome_total{outcome="valid"|"invalid"}
//   - js_spoa_handler_seconds_bucket|sum|count{message="issue-token"|"verify-token"}
//   - js_spoa_build_info{version="<ldflags-set>"}
//
// Build (embed version):
//   go build -trimpath -ldflags "-s -w -X 'main.version=$(git describe --tags --always || echo dev)'" -o bin/js-spoa ./cmd/js-spoa
//
// Run (dev):
//   ./bin/js-spoa -listen 127.0.0.1:9903 -metrics 127.0.0.1:9904 -secret /etc/js-spoa/secret.key -ttl 1h
//
// Token details:
//   token = base64url(payload) + "." + base64url(HMAC_SHA256(secret, payload))
//   payload = ip|ua_sha1|iat|exp|nonce
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

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Version is set at build time with -ldflags "-X 'main.version=...'"
var version = "dev"

// CLI flags
var (
	listenAddr  = flag.String("listen", "127.0.0.1:9903", "SPOE listen address")
	metricsAddr = flag.String("metrics", "127.0.0.1:9904", "Metrics/health listen address (empty to disable)")
	secretPath  = flag.String("secret", "/etc/js-spoa/secret.key", "Primary secret file path")
	ttl         = flag.Duration("ttl", 1*time.Hour, "Token TTL (e.g., 1h)")
	skew        = flag.Duration("skew", 30*time.Second, "Clock skew allowance")
)

// Secret storage (atomic swap on SIGHUP)
type secrets struct{ primary []byte }

var sec atomic.Pointer[secrets]

// ---------------- Prometheus metrics ----------------

var (
	// Counters
	mIssueTotal  = prometheus.NewCounter(prometheus.CounterOpts{Name: "js_spoa_issue_total", Help: "Total number of issued challenge tokens"})
	mVerifyTotal = prometheus.NewCounter(prometheus.CounterOpts{Name: "js_spoa_verify_total", Help: "Total number of verify requests"})

	// CounterVec with outcome label for verification
	mVerifyOutcome = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "js_spoa_verify_outcome_total",
			Help: "Verify outcomes by result",
		},
		[]string{"outcome"}, // "valid" or "invalid"
	)

	// Handler latency histograms
	mHandlerSeconds = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "js_spoa_handler_seconds",
			Help:    "Time spent handling SPOE messages",
			Buckets: prometheus.DefBuckets, // 5ms .. 10s typical
		},
		[]string{"message"}, // "issue-token" or "verify-token"
	)

	// Build info gauge
	mBuildInfo = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "js_spoa_build_info",
			Help: "Build information",
		},
		[]string{"version"},
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

// ---------------- token issue / verify ----------------

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

// ---------------- Negasus handler ----------------

func makeHandler() func(*request.Request) {
	return func(req *request.Request) {
		// "issue-token"
		if mes, err := req.Messages.GetByName("issue-token"); err == nil {
			tStart := time.Now()
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
			var ipStr, ua, cookie string
			mVerifyTotal.Inc()

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
				mVerifyOutcome.WithLabelValues("valid").Inc()
			} else {
				mVerifyOutcome.WithLabelValues("invalid").Inc()
			}
			req.Actions.SetVar(action.ScopeTransaction, "valid", valid)
			mHandlerSeconds.WithLabelValues("verify-token").Observe(time.Since(tStart).Seconds())
		}
	}
}

// ---------------- main ----------------

func main() {
	flag.Parse()

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

	log.Printf("js-spoa %s listening on %s (metrics: %s)", version, *listenAddr, *metricsAddr)

	h := makeHandler()
	a := agent.New(h, logger.NewDefaultLog())

	// Metrics server
	if *metricsAddr != "" {
		// register metrics
		prometheus.MustRegister(mIssueTotal, mVerifyTotal, mVerifyOutcome, mHandlerSeconds, mBuildInfo)
		mBuildInfo.WithLabelValues(version).Set(1)

		go func() {
			mux := http.NewServeMux()
			mux.Handle("/metrics", promhttp.Handler())
			mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("ok\n"))
			})
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

