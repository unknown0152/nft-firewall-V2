package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/unknown0152/nft-firewall-v2/internal/api"
	"github.com/unknown0152/nft-firewall-v2/internal/app"
	"github.com/unknown0152/nft-firewall-v2/internal/compiler"
	"github.com/unknown0152/nft-firewall-v2/internal/health"
	"github.com/unknown0152/nft-firewall-v2/internal/nft"
	"github.com/unknown0152/nft-firewall-v2/internal/state"
	"github.com/unknown0152/nft-firewall-v2/internal/version"
)

type doctorChecksRunner struct {
	sequence *[]string
}

type requestRecorder struct {
	mu       sync.Mutex
	requests []api.Request
}

func (r *requestRecorder) append(request api.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requests = append(r.requests, request)
}

func (r *requestRecorder) operations() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make([]string, len(r.requests))
	for index, request := range r.requests {
		result[index] = request.Op
	}
	return result
}

func startTestAPISocket(t *testing.T, path string, status any, recorder *requestRecorder) {
	t.Helper()
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	t.Cleanup(func() {
		close(done)
		_ = listener.Close()
		_ = os.Remove(path)
	})
	go func() {
		for {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				select {
				case <-done:
					return
				default:
					return
				}
			}
			go func(conn net.Conn) {
				defer conn.Close()
				var request api.Request
				if json.NewDecoder(conn).Decode(&request) != nil {
					return
				}
				recorder.append(request)
				data := any(map[string]any{"operation": request.Op})
				if request.Op == "status" {
					data = status
				}
				_ = json.NewEncoder(conn).Encode(api.Response{OK: true, Data: data})
			}(connection)
		}
	}()
}

func (r doctorChecksRunner) Run(_ context.Context, args ...string) (string, string, error) {
	if len(args) == 3 && args[0] == "-j" && args[1] == "list" && args[2] == "ruleset" {
		*r.sequence = append(*r.sequence, "foreign-audit")
		return `{"nftables":[{"metainfo":{"json_schema_version":1}}]}`, "", nil
	}
	if len(args) == 3 && args[0] == "-j" && args[1] == "list" && args[2] == "tables" {
		return `{"nftables":[]}`, "", nil
	}
	if len(args) >= 2 && args[0] == "--check" && args[1] == "--file" {
		*r.sequence = append(*r.sequence, "candidate-check")
		return "", "", nil
	}
	return "", "", nil
}

func TestDoctorPreflightsBeforeGlobalLockAndRevalidatesUnderIt(t *testing.T) {
	lockDir := t.TempDir()
	if err := os.Chmod(lockDir, 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var sequence []string
	preflight := func(preflightCtx context.Context) error {
		sequence = append(sequence, "preflight")
		release, err := state.AcquireMutationLock(preflightCtx, lockDir)
		if err != nil {
			return err
		}
		release()
		return nil
	}
	revalidate := func(lockedCtx context.Context) error {
		sequence = append(sequence, "locked-revalidation")
		if !state.MutationLockHeld(lockedCtx) {
			return errors.New("doctor revalidation lacks held-lock marker")
		}
		waitCtx, waitCancel := context.WithTimeout(lockedCtx, 30*time.Millisecond)
		defer waitCancel()
		if release, err := state.AcquireMutationLock(waitCtx, lockDir); err == nil {
			release()
			return errors.New("doctor revalidation ran without the actual global lock")
		}
		return nil
	}
	backend := nft.New(doctorChecksRunner{sequence: &sequence})
	if _, err := doctorProtectedChecks(ctx, lockDir, backend, "table inet nftfw_filter { }\n", preflight, revalidate); err != nil {
		t.Fatal(err)
	}
	want := []string{"preflight", "foreign-audit", "candidate-check", "locked-revalidation"}
	if strings.Join(sequence, ",") != strings.Join(want, ",") {
		t.Fatalf("doctor check order=%v want=%v", sequence, want)
	}
	release, err := state.AcquireMutationLock(ctx, lockDir)
	if err != nil {
		t.Fatalf("doctor did not release global lock: %v", err)
	}
	release()
}

func TestStateBackupAndVerify(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	database := filepath.Join(dir, "state.db")
	backup := filepath.Join(dir, "backup", "state.db")
	store, err := state.Open(context.Background(), database)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	runtimeDir := t.TempDir()
	if err := os.Chmod(runtimeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NFTFW_RUNTIME_DIR", runtimeDir)
	if err := stateCommand([]string{"verify", "--database", database}); err != nil {
		t.Fatal(err)
	}
	if err := stateCommand([]string{"backup", backup, "--database", database}); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(backup); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("backup missing or unsafe: info=%v err=%v", info, err)
	}
	if err := stateCommand([]string{"backup", "relative.db", "--database", database}); err == nil {
		t.Fatal("relative backup destination accepted")
	}
}

func TestStateOfflineMigrationCommand(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(root, "legacy.db")
	backup := filepath.Join(root, "backups", "legacy.db")
	destination := filepath.Join(root, "generation-state", "state.db")
	db, err := sql.Open("sqlite", source)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`
CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
CREATE TABLE generations (
 id INTEGER PRIMARY KEY, checksum TEXT NOT NULL, script_path TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('pending','applied','committed','rolled_back')),
 created_at TEXT NOT NULL, rollback_deadline TEXT,
 previous_id INTEGER REFERENCES generations(id)
);
CREATE INDEX generations_status_idx ON generations(status);
CREATE TABLE claims (
 id INTEGER PRIMARY KEY AUTOINCREMENT, address TEXT NOT NULL,
 family TEXT NOT NULL CHECK(family IN ('ipv4','ipv6')), source TEXT NOT NULL,
 reason TEXT NOT NULL, actor TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT
);
CREATE INDEX claims_address_idx ON claims(address, family);
CREATE TABLE audit (
 id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL,
 actor TEXT NOT NULL, event TEXT NOT NULL, detail TEXT NOT NULL
);
INSERT INTO schema_migrations VALUES(1, '2026-01-01T00:00:00Z');
`)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(source, 0o600); err != nil {
		t.Fatal(err)
	}
	runtimeDir := t.TempDir()
	if err := os.Chmod(runtimeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NFTFW_RUNTIME_DIR", runtimeDir)
	if err := stateCommand([]string{
		"migrate", destination,
		"--database", source,
		"--backup", backup,
	}); err != nil {
		t.Fatal(err)
	}
	if err := stateCommand([]string{"verify", "--database", destination}); err != nil {
		t.Fatal(err)
	}
	sourceBytes, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	backupBytes, err := os.ReadFile(backup)
	if err != nil {
		t.Fatal(err)
	}
	if string(sourceBytes) != string(backupBytes) {
		t.Fatal("state migrate backup is not byte-identical")
	}
	if err := stateCommand([]string{"migrate", filepath.Join(root, "other.db"), "--database", source}); err == nil {
		t.Fatal("state migrate accepted a missing --backup")
	}
}

func TestHealthContractFailsClosed(t *testing.T) {
	const policyHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	healthy := health.Snapshot{
		Schema: health.StatusSchema, Status: "HEALTHY", Active: true,
		PolicyMatch: true, KillSwitchEnforced: true, PolicyHash: policyHash, PolicyChecksum: policyHash,
	}
	if !statusHealthy(healthy) {
		t.Fatal("complete healthy status contract was rejected")
	}
	mutations := []func(*health.Snapshot){
		func(s *health.Snapshot) { s.Schema = "" },
		func(s *health.Snapshot) { s.Status = "DEGRADED" },
		func(s *health.Snapshot) { s.Active = false },
		func(s *health.Snapshot) { s.PolicyMatch = false },
		func(s *health.Snapshot) { s.KillSwitchEnforced = false },
		func(s *health.Snapshot) { s.PolicyHash = "" },
		func(s *health.Snapshot) { s.PolicyHash = strings.ToUpper(policyHash) },
		func(s *health.Snapshot) { s.PolicyChecksum = "" },
		func(s *health.Snapshot) { s.PolicyChecksum = strings.Repeat("f", 64) },
	}
	for index, mutate := range mutations {
		candidate := healthy
		mutate(&candidate)
		if statusHealthy(candidate) {
			t.Fatalf("incomplete status contract %d was accepted: %#v", index, candidate)
		}
	}
}

func TestStateCommandRejectsUnknownArguments(t *testing.T) {
	if err := stateCommand([]string{"restore", "/tmp/state.db"}); err == nil {
		t.Fatal("unsupported destructive restore command accepted")
	}
	if err := stateCommand([]string{"verify", "extra"}); err == nil {
		t.Fatal("unexpected state argument accepted")
	}
}

func TestStateDatabaseFlagOverridesEnvironment(t *testing.T) {
	t.Setenv("NFTFW_STATE_DB", filepath.Join(t.TempDir(), "environment.db"))
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	database := filepath.Join(directory, "flag.db")
	store, err := state.Open(context.Background(), database)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := stateCommand([]string{"verify", "--database", database}); err != nil {
		t.Fatal(err)
	}
}

func TestStateVerifyNeverCreatesOrMigratesMissingState(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	database := filepath.Join(directory, "missing.db")
	if err := stateCommand([]string{"verify", "--database", database}); err == nil {
		t.Fatal("missing database was accepted")
	}
	if _, err := os.Lstat(database); !os.IsNotExist(err) {
		t.Fatalf("verify created missing state: %v", err)
	}
}

func TestSecuritySensitiveCommandsRejectTrailingArguments(t *testing.T) {
	for _, args := range [][]string{
		{"version", "extra"},
		{"apply", "--safe", "--safe"},
		{"commit", "1", "extra"},
		{"rollback", "0"},
		{"reconcile", "extra"},
		{"blocks", "list", "extra"},
		{"block", "remove", "1", "extra"},
		{"wg", "status", "extra"},
	} {
		if err := run(args); err == nil {
			t.Fatalf("ambiguous command accepted: %#v", args)
		}
	}
}

func TestStageRCandidateOnlyAllowsVersionAndNothingElse(t *testing.T) {
	previous := version.BuildDisposition
	previousVersion := version.Version
	version.BuildDisposition = version.StageRCandidateOnly
	t.Cleanup(func() {
		version.BuildDisposition = previous
		version.Version = previousVersion
	})

	for _, args := range [][]string{{"version"}, {"version", "--json"}} {
		if err := run(args); err != nil {
			t.Fatalf("candidate version command %v was rejected: %v", args, err)
		}
	}
	for _, args := range [][]string{
		{"config", "validate", "/does/not/exist"},
		{"plan"},
		{"status"},
		{"state", "verify"},
	} {
		err := run(args)
		if err == nil || !strings.Contains(err.Error(), "candidate-only build is quarantined") {
			t.Fatalf("candidate command %v did not fail at the quarantine gate: %v", args, err)
		}
	}
	version.BuildDisposition = "release"
	version.Version = "2.0.3~stage.r.aaaaaaaaaaaa"
	if err := run([]string{"status"}); err == nil || !strings.Contains(err.Error(), "candidate-only build is quarantined") {
		t.Fatalf("candidate version escaped CLI quarantine under forged disposition: %v", err)
	}
}

func TestPlanDiffAndDisplayHelpers(t *testing.T) {
	policies := diffPolicies(
		map[string]string{"keep": "allow", "remove": "drop", "change": "allow"},
		map[string]string{"keep": "allow", "add": "allow", "change": "drop"},
	)
	if strings.Join(policies, ",") != "+ allow add,- drop remove,~ change allow -> drop" {
		t.Fatalf("unexpected policy diff: %v", policies)
	}
	names := diffNames([]string{"keep", "remove"}, []string{"keep", "add"})
	if strings.Join(names, ",") != "+ add,- remove" {
		t.Fatalf("unexpected name diff: %v", names)
	}
	sets := summarizeSetChanges(
		map[string][]string{"blocked_v4": {"one"}},
		map[string][]string{"blocked_v4": {"one", "two"}},
	)
	if sets["blocked_v4"] != "1 -> 2" || sets["docker_nets"] != "0 -> 0" {
		t.Fatalf("unexpected set summary: %v", sets)
	}
	if displayChanges(nil) != "= no semantic changes" ||
		!strings.Contains(displaySetChanges(sets), "blocked_v4: 1 -> 2") {
		t.Fatal("diff display helpers changed")
	}
}

func TestGeneralCLIHelpers(t *testing.T) {
	if id, err := parseID([]string{"commit", "7"}, 1); err != nil || id != 7 {
		t.Fatalf("generation parse failed: %d %v", id, err)
	}
	for _, args := range [][]string{{"commit"}, {"commit", "0"}, {"commit", "bad"}} {
		if _, err := parseID(args, 1); err == nil {
			t.Fatalf("invalid generation accepted: %v", args)
		}
	}
	if !has([]string{"--json"}, "--json") || has(nil, "--json") ||
		!contains([]string{"eth0"}, "eth0") || contains([]string{"eth0"}, "wg0") {
		t.Fatal("membership helpers changed")
	}
	if err := printJSONOr(map[string]any{"ok": true}, true); err != nil {
		t.Fatal(err)
	}
	if err := printJSONOr("plain", false); err != nil {
		t.Fatal(err)
	}
	if err := printJSONOr(make(chan int), true); err == nil {
		t.Fatal("unencodable JSON output accepted")
	}
}

func TestSecurePathHelpers(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := secureExistingDirectory(root); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o722); err != nil {
		t.Fatal(err)
	}
	if err := secureExistingDirectory(root); err == nil {
		t.Fatal("writable directory accepted")
	}
	if err := secureSecretFile("relative"); err == nil {
		t.Fatal("relative secret path accepted")
	}
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := secureSecretFile(secret); err == nil {
		t.Fatal("world-readable secret accepted")
	}
}

func TestSimpleRunBranches(t *testing.T) {
	if err := run([]string{"version"}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"version", "--json"}); err != nil {
		t.Fatal(err)
	}
	exampleSource := filepath.Join("..", "..", "configs", "nftfw.example.toml")
	exampleData, err := os.ReadFile(exampleSource)
	if err != nil {
		t.Fatal(err)
	}
	exampleDir := t.TempDir()
	if err := os.Chmod(exampleDir, 0o700); err != nil {
		t.Fatal(err)
	}
	exampleConfig := filepath.Join(exampleDir, "nftfw.toml")
	if err := os.WriteFile(exampleConfig, exampleData, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"config", "validate", exampleConfig}); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		nil,
		{"unknown"},
		{"config"},
		{"plan", "--bad"},
		{"apply", "--safe", "--unsafe"},
		{"reconcile", "extra"},
		{"doctor", "extra"},
		{"audit", "extra"},
		{"blocks", "bad"},
		{"block", "bad", "value"},
		{"explain", "--protocol", "bad"},
	} {
		if err := run(args); err == nil {
			t.Fatalf("invalid run branch accepted: %v", args)
		}
	}
}

func TestRunRemoteCommandContracts(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	statusSocket := filepath.Join(root, "status.sock")
	controlSocket := filepath.Join(root, "control.sock")
	digest := strings.Repeat("a", sha256HexLength)
	snapshot := health.Snapshot{
		Schema: health.StatusSchema, Status: "HEALTHY", Active: true,
		PolicyMatch: true, KillSwitchEnforced: true,
		PolicyHash: digest, PolicyChecksum: digest,
	}
	recorder := &requestRecorder{}
	startTestAPISocket(t, statusSocket, snapshot, recorder)
	startTestAPISocket(t, controlSocket, snapshot, recorder)
	t.Setenv("NFTFW_STATUS_SOCKET", statusSocket)
	t.Setenv("NFTFW_CONTROL_SOCKET", controlSocket)

	commands := [][]string{
		{"status"},
		{"status", "--json"},
		{"health"},
		{"health", "--json"},
		{"audit"},
		{"apply", "--safe"},
		{"apply", "--unsafe"},
		{"commit", "7"},
		{"rollback", "7"},
		{"reconcile"},
		{"blocks", "list", "--limit", "5", "--offset", "1"},
		{"block", "add", "192.0.2.10/32", "--ttl", "1h", "scanner"},
		{"block", "remove", "11"},
		{"allow", "add", "192.0.2.20/32", "temporary"},
		{"allow", "remove", "12"},
		{"wg", "refresh"},
	}
	for _, command := range commands {
		if err := run(command); err != nil {
			t.Fatalf("%v failed: %v", command, err)
		}
	}
	want := []string{
		"status", "status", "status", "status", "audit", "apply", "apply",
		"commit", "rollback", "reconcile", "claims", "block-add",
		"block-remove", "allow-add", "allow-remove", "wg-refresh",
	}
	if got := recorder.operations(); !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected API operations: %v", got)
	}
}

func TestExecutableAndControlFallbackBoundaries(t *testing.T) {
	_ = secureCurrentExecutable()
	t.Setenv("NFTFW_LOCAL", "")
	if err := controlOrLocal(
		filepath.Join(t.TempDir(), "missing.sock"),
		filepath.Join(t.TempDir(), "missing.toml"),
		api.Request{Op: "reconcile"},
		func(*app.Runtime) (any, error) { return nil, nil },
	); err == nil || !strings.Contains(err.Error(), "control socket unavailable") {
		t.Fatalf("missing daemon fallback was accepted: %v", err)
	}
}

func BenchmarkSemanticSummaryAndDiff(b *testing.B) {
	currentScript := `add table inet nftfw_filter
add rule inet nftfw_filter input comment "nftfw:policy:lan-ssh:allow"
add element inet nftfw_filter blocked_v4 { 192.0.2.1/32 }
`
	proposedScript := `add table inet nftfw_filter
add rule inet nftfw_filter input comment "nftfw:policy:lan-ssh:allow"
add rule inet nftfw_filter input comment "nftfw:policy:vpn-web:allow"
add element inet nftfw_filter blocked_v4 { 192.0.2.1/32, 192.0.2.2/32 }
`
	b.ReportAllocs()
	for b.Loop() {
		current := compiler.SummarizeScript(currentScript)
		proposed := compiler.SummarizeScript(proposedScript)
		_ = diffPolicies(current.Policies, proposed.Policies)
		_ = diffNames(current.NAT, proposed.NAT)
		_ = summarizeSetChanges(current.Sets, proposed.Sets)
	}
}
