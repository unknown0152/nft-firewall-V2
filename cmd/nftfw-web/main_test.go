package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/unknown0152/nft-firewall-v2/internal/version"
)

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
	version.Version = "2.0.2~stage.r.aaaaaaaaaaaa"
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
		"data.schema==='nftfw.status.v1'",
		"data.active===true",
		"data.policy_match===true",
		"data.kill_switch_enforced===true",
		"Object.prototype.hasOwnProperty.call(data,'policy_hash')",
		"typeof primaryHash==='string'",
		"primaryHash===checksum",
		"&&hashValid",
		"data.protected===true",
		"data.status==='HEALTHY'&&contract",
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
		"schema": "nftfw.status.v1", "status": "HEALTHY", "active": true,
		"policy_match": true, "kill_switch_enforced": true, "policy_hash": hash, "policy_checksum": hash,
	}
	if !dashboardProtected(healthy) {
		t.Fatal("valid protected contract was rejected")
	}
	mutations := []func(map[string]any){
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
