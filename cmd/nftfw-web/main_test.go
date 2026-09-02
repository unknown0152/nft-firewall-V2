package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/unknown0152/nft-firewall-v2/internal/api"
	"github.com/unknown0152/nft-firewall-v2/internal/version"
)

type dashboardStatusHandler struct {
	mu        sync.Mutex
	responses []map[string]any
	calls     int
	wait      <-chan struct{}
	entered   *atomic.Int64
	blockOnce atomic.Bool
}

func (h *dashboardStatusHandler) Status(ctx context.Context) (any, error) {
	if h.entered != nil {
		h.entered.Add(1)
	}
	if h.blockOnce.CompareAndSwap(true, false) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if h.wait != nil {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-h.wait:
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	index := h.calls
	h.calls++
	if index >= len(h.responses) {
		index = len(h.responses) - 1
	}
	result := make(map[string]any, len(h.responses[index]))
	for key, value := range h.responses[index] {
		result[key] = value
	}
	return result, nil
}

func (*dashboardStatusHandler) Control(context.Context, api.Request) (any, error) {
	return nil, errors.New("not used")
}

func healthyDashboardStatus() map[string]any {
	const hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	return map[string]any{
		"schema": "nftfw.status.v2", "status": "HEALTHY", "active": true,
		"policy_match": true, "kill_switch_enforced": true,
		"policy_hash": hash, "policy_checksum": hash,
	}
}

func startDashboardStatusSocket(tb testing.TB, handler api.Handler) (string, context.CancelFunc) {
	tb.Helper()
	directory := tb.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		tb.Fatal(err)
	}
	statusPath := filepath.Join(directory, "status.sock")
	server := &api.Server{
		Handler: handler, StatusPath: statusPath,
		ControlPath: filepath.Join(directory, "control.sock"),
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Lstat(statusPath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			tb.Fatal("status socket did not become ready")
		}
		time.Sleep(time.Millisecond)
	}
	stop := func() {
		cancel()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, context.Canceled) {
				tb.Errorf("stop status server: %v", err)
			}
		case <-time.After(2 * time.Second):
			tb.Error("status server did not stop")
		}
	}
	tb.Cleanup(stop)
	return statusPath, cancel
}

func TestStageRCandidateOnlyRefusesWebStartup(t *testing.T) {
	previous := version.BuildDisposition
	previousVersion := version.Version
	version.BuildDisposition = version.StageRCandidateOnly
	t.Cleanup(func() {
		version.BuildDisposition = previous
		version.Version = previousVersion
	})

	if err := candidateStartupGuard(); err == nil {
		t.Fatal("candidate-only nftfw-web startup was accepted")
	}
	version.BuildDisposition = "development"
	version.Version = "2.0.3~stage.r.aaaaaaaaaaaa"
	if err := candidateStartupGuard(); err == nil {
		t.Fatal("candidate-version nftfw-web startup was accepted under a forged disposition")
	}
	version.Version = previousVersion
	if err := candidateStartupGuard(); err != nil {
		t.Fatalf("development nftfw-web startup guard failed: %v", err)
	}
}

func TestDashboardIsReadOnlyAndUsesSameOriginAssets(t *testing.T) {
	handler := newHandler("/nonexistent/nftfw-status.sock")
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "/assets/app.css") || strings.Contains(response.Body.String(), "unsafe-inline") {
		t.Fatalf("unexpected dashboard response: code=%d body=%s", response.Code, response.Body.String())
	}
	for _, header := range []string{"Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options", "Permissions-Policy"} {
		if response.Header().Get(header) == "" {
			t.Fatalf("missing security header %s", header)
		}
	}
	request = httptest.NewRequest(http.MethodPost, "/api/status", strings.NewReader("{}"))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("mutable method accepted: %d", response.Code)
	}
	request = httptest.NewRequest(http.MethodGet, "/unknown", nil)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("unknown path did not return 404: %d", response.Code)
	}
}

func TestDashboardStatusErrorDoesNotDiscloseSocketDetails(t *testing.T) {
	handler := newHandler("/private/path/status.sock")
	request := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("unexpected response code: %d", response.Code)
	}
	body, _ := io.ReadAll(response.Result().Body)
	if strings.Contains(string(body), "/private/") {
		t.Fatalf("socket path disclosed: %s", body)
	}
}

func TestDashboardUsesFailClosedStatusContract(t *testing.T) {
	for _, required := range []string{
		"data.schema==='nftfw.status.v2'",
		"data.active===true",
		"data.policy_match===true",
		"data.kill_switch_enforced===true",
		"Object.prototype.hasOwnProperty.call(data,'policy_hash')",
		"typeof primaryHash==='string'",
		"primaryHash===checksum",
		"&&hashValid",
		"data.protected===true",
		"data.status==='HEALTHY'&&contract",
		"data.managed===true?'Managed':'Advanced'",
		"ports(data.public_tcp,data.public_udp)",
	} {
		if !strings.Contains(appJS, required) {
			t.Fatalf("dashboard is missing strict status check %q", required)
		}
	}
	if strings.Contains(appJS, "!!data.status") {
		t.Fatal("dashboard uses status-string truthiness")
	}
}

func TestDashboardProtectedRejectsMissingAndWrongTypedFields(t *testing.T) {
	const hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	healthy := map[string]any{
		"schema": "nftfw.status.v2", "status": "HEALTHY", "active": true,
		"policy_match": true, "kill_switch_enforced": true, "policy_hash": hash, "policy_checksum": hash,
	}
	if !dashboardProtected(healthy) {
		t.Fatal("valid protected contract was rejected")
	}
	mutations := []func(map[string]any){
		func(value map[string]any) { value["schema"] = "nftfw.status.v1" },
		func(value map[string]any) { delete(value, "policy_hash") },
		func(value map[string]any) { value["policy_hash"] = 0 },
		func(value map[string]any) { value["policy_hash"] = false },
		func(value map[string]any) { value["policy_hash"] = strings.ToUpper(hash) },
		func(value map[string]any) { value["policy_checksum"] = 0 },
		func(value map[string]any) { value["policy_checksum"] = strings.Repeat("f", 64) },
		func(value map[string]any) { value["active"] = "true" },
	}
	for index, mutate := range mutations {
		candidate := make(map[string]any, len(healthy))
		for key, value := range healthy {
			candidate[key] = value
		}
		mutate(candidate)
		if dashboardProtected(candidate) {
			t.Fatalf("invalid protected contract %d was accepted: %#v", index, candidate)
		}
	}
}

func TestDashboardAdjacentUnixResponsesNeverInheritProtectedState(t *testing.T) {
	healthy := healthyDashboardStatus()
	degraded := healthyDashboardStatus()
	degraded["policy_match"] = false
	handler := &dashboardStatusHandler{responses: []map[string]any{healthy, degraded}}
	statusPath, _ := startDashboardStatusSocket(t, handler)
	server := httptest.NewServer(newHandler(statusPath))
	t.Cleanup(server.Close)

	for index, want := range []bool{true, false} {
		response, err := server.Client().Get(server.URL + "/api/status")
		if err != nil {
			t.Fatal(err)
		}
		var payload map[string]any
		decodeErr := json.NewDecoder(response.Body).Decode(&payload)
		response.Body.Close()
		if decodeErr != nil || response.StatusCode != http.StatusOK || payload["protected"] != want {
			t.Fatalf("response %d inherited stale protection: code=%d payload=%#v err=%v", index, response.StatusCode, payload, decodeErr)
		}
	}
}

func TestDashboardCancellationClosesUnixRequestAndRecovers(t *testing.T) {
	handler := &dashboardStatusHandler{responses: []map[string]any{healthyDashboardStatus()}}
	handler.blockOnce.Store(true)
	statusPath, _ := startDashboardStatusSocket(t, handler)
	server := httptest.NewServer(newHandler(statusPath))
	t.Cleanup(server.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/api/status", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := server.Client().Do(request)
	cancel()
	if response != nil {
		response.Body.Close()
	}
	if err == nil {
		t.Fatal("canceled dashboard request unexpectedly completed")
	}

	response, err = server.Client().Get(server.URL + "/api/status")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("dashboard did not recover after cancellation: %d", response.StatusCode)
	}
}

func TestDashboardConcurrentStatusSaturationIsBounded(t *testing.T) {
	release := make(chan struct{})
	entered := &atomic.Int64{}
	handler := &dashboardStatusHandler{
		responses: []map[string]any{healthyDashboardStatus()},
		wait:      release, entered: entered,
	}
	statusPath, _ := startDashboardStatusSocket(t, handler)
	server := httptest.NewServer(newHandler(statusPath))
	t.Cleanup(server.Close)
	transport := &http.Transport{DisableKeepAlives: true, MaxConnsPerHost: 128}
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	t.Cleanup(transport.CloseIdleConnections)

	const requests = api.MaxConcurrentStatusConnections + 32
	results := make(chan int, requests)
	var workers sync.WaitGroup
	for range requests {
		workers.Add(1)
		go func() {
			defer workers.Done()
			response, err := client.Get(server.URL + "/api/status")
			if err != nil {
				results <- 0
				return
			}
			_, _ = io.Copy(io.Discard, response.Body)
			response.Body.Close()
			results <- response.StatusCode
		}()
	}
	deadline := time.Now().Add(2 * time.Second)
	for entered.Load() < api.MaxConcurrentStatusConnections && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if entered.Load() != api.MaxConcurrentStatusConnections {
		close(release)
		workers.Wait()
		t.Fatalf("status concurrency was not capped at %d: %d", api.MaxConcurrentStatusConnections, entered.Load())
	}
	firstCode := 0
	select {
	case firstCode = <-results:
		if firstCode != http.StatusServiceUnavailable {
			close(release)
			workers.Wait()
			t.Fatalf("saturated status request was not rejected while all slots were held: %d", firstCode)
		}
	case <-time.After(2 * time.Second):
		close(release)
		workers.Wait()
		t.Fatal("status saturation produced no bounded rejection while all slots were held")
	}
	close(release)
	workers.Wait()
	close(results)
	accepted, rejected := 0, 1
	for code := range results {
		switch code {
		case http.StatusOK:
			accepted++
		case http.StatusServiceUnavailable:
			rejected++
		default:
			t.Fatalf("unexpected saturated response: %d", code)
		}
	}
	if accepted < api.MaxConcurrentStatusConnections || accepted+rejected != requests {
		t.Fatalf("unbounded or unavailable status service: accepted=%d rejected=%d", accepted, rejected)
	}
}

func TestDashboardRepeatedStatusDoesNotLeakDescriptorsOrGoroutines(t *testing.T) {
	handler := &dashboardStatusHandler{responses: []map[string]any{healthyDashboardStatus()}}
	statusPath, _ := startDashboardStatusSocket(t, handler)
	server := httptest.NewServer(newHandler(statusPath))
	t.Cleanup(server.Close)
	transport := &http.Transport{DisableKeepAlives: true}
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	t.Cleanup(transport.CloseIdleConnections)

	fdCount := func() int {
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Skipf("Linux descriptor accounting is unavailable: %v", err)
		}
		return len(entries)
	}
	beforeFDs := fdCount()
	beforeGoroutines := runtime.NumGoroutine()
	for range 256 {
		response, err := client.Get(server.URL + "/api/status")
		if err != nil {
			t.Fatal(err)
		}
		_, readErr := io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if readErr != nil || response.StatusCode != http.StatusOK {
			t.Fatalf("repeated dashboard status failed: code=%d err=%v", response.StatusCode, readErr)
		}
	}
	transport.CloseIdleConnections()
	deadline := time.Now().Add(2 * time.Second)
	var afterFDs, afterGoroutines int
	for {
		runtime.GC()
		afterFDs = fdCount()
		afterGoroutines = runtime.NumGoroutine()
		if afterFDs <= beforeFDs+2 && afterGoroutines <= beforeGoroutines+8 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf(
				"repeated status retained resources: fds=%d->%d goroutines=%d->%d",
				beforeFDs, afterFDs, beforeGoroutines, afterGoroutines,
			)
		}
		time.Sleep(10 * time.Millisecond)
	}
	handler.mu.Lock()
	calls := handler.calls
	handler.mu.Unlock()
	if calls != 256 {
		t.Fatalf("repeated status lost or reused observations: %d", calls)
	}
}

func BenchmarkDashboardProtected(b *testing.B) {
	const hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	healthy := map[string]any{
		"schema": "nftfw.status.v2", "status": "HEALTHY", "active": true,
		"policy_match": true, "kill_switch_enforced": true,
		"policy_hash": hash, "policy_checksum": hash,
	}
	b.ReportAllocs()
	for b.Loop() {
		if !dashboardProtected(healthy) {
			b.Fatal("healthy fixture rejected")
		}
	}
}

func BenchmarkDashboardStatusTransportEndToEnd(b *testing.B) {
	handler := &dashboardStatusHandler{responses: []map[string]any{healthyDashboardStatus()}}
	statusPath, _ := startDashboardStatusSocket(b, handler)
	server := httptest.NewServer(newHandler(statusPath))
	b.Cleanup(server.Close)
	client := server.Client()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		response, err := client.Get(server.URL + "/api/status")
		if err != nil {
			b.Fatal(err)
		}
		_, readErr := io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if readErr != nil || response.StatusCode != http.StatusOK {
			b.Fatalf("dashboard status failed: code=%d err=%v", response.StatusCode, readErr)
		}
	}
}
