package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

type result struct {
	latency time.Duration
	failed  bool
}

func main() {
	base := env("IDENTITYMESH_LOAD_BASE_URL", "http://load-balancer:8080")
	users := envInt("IDENTITYMESH_LOAD_USERS", 100)
	requests := envInt("IDENTITYMESH_LOAD_REQUESTS_PER_USER", 100)
	maxP95 := time.Duration(envInt("IDENTITYMESH_LOAD_MAX_P95_MS", 750)) * time.Millisecond
	maxErrors := float64(envInt("IDENTITYMESH_LOAD_MAX_ERROR_PERMILLE", 10)) / 1000
	client := &http.Client{Timeout: 10 * time.Second}
	cookie, err := login(client, base)
	if err != nil {
		fatal("load login failed: %v", err)
	}
	started := time.Now()
	results := make(chan result, users*requests)
	var wg sync.WaitGroup
	for i := 0; i < users; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < requests; n++ {
				before := time.Now()
				req, _ := http.NewRequest(http.MethodGet, base+"/api/v1/dashboard", nil)
				req.AddCookie(cookie)
				resp, requestErr := client.Do(req)
				failed := requestErr != nil
				if resp != nil {
					_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
					resp.Body.Close()
					failed = failed || resp.StatusCode != http.StatusOK
				}
				results <- result{latency: time.Since(before), failed: failed}
			}
		}()
	}
	wg.Wait()
	close(results)
	latencies := make([]time.Duration, 0, users*requests)
	var failures atomic.Int64
	for item := range results {
		latencies = append(latencies, item.latency)
		if item.failed {
			failures.Add(1)
		}
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	p95 := latencies[int(float64(len(latencies)-1)*0.95)]
	duration := time.Since(started)
	errorRate := float64(failures.Load()) / float64(len(latencies))
	rps := float64(len(latencies)) / duration.Seconds()
	report := map[string]any{"virtualUsers": users, "requests": len(latencies), "failures": failures.Load(), "errorRate": errorRate, "p95Milliseconds": float64(p95.Microseconds()) / 1000, "requestsPerSecond": rps, "duration": duration.String(), "thresholds": map[string]any{"maxP95": maxP95.String(), "maxErrorRate": maxErrors}}
	encoded, _ := json.Marshal(report)
	fmt.Println(string(encoded))
	if p95 > maxP95 || errorRate > maxErrors {
		os.Exit(1)
	}
}
func login(client *http.Client, base string) (*http.Cookie, error) {
	body, _ := json.Marshal(map[string]string{"email": env("IDENTITYMESH_LOAD_EMAIL", "load@example.test"), "password": env("IDENTITYMESH_LOAD_PASSWORD", "load-test-password-only")})
	resp, err := client.Post(base+"/api/v1/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, raw)
	}
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "identitymesh_session" {
			return cookie, nil
		}
	}
	return nil, fmt.Errorf("session cookie missing")
}
func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
func envInt(key string, fallback int) int {
	value, err := strconv.Atoi(os.Getenv(key))
	if err != nil || value < 1 {
		return fallback
	}
	return value
}
func fatal(format string, args ...any) { fmt.Fprintf(os.Stderr, format+"\n", args...); os.Exit(1) }
