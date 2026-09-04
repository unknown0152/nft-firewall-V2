package main

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/unknown0152/nft-firewall-v2/internal/adoption"
	"github.com/unknown0152/nft-firewall-v2/internal/api"
	"github.com/unknown0152/nft-firewall-v2/internal/health"
	"github.com/unknown0152/nft-firewall-v2/internal/intent"
	"github.com/unknown0152/nft-firewall-v2/internal/netgate"
	"github.com/unknown0152/nft-firewall-v2/internal/provenance"
	"github.com/unknown0152/nft-firewall-v2/internal/reconcile"
	"github.com/unknown0152/nft-firewall-v2/internal/routing"
	managedsetup "github.com/unknown0152/nft-firewall-v2/internal/setup"
	"github.com/unknown0152/nft-firewall-v2/internal/state"
	"github.com/unknown0152/nft-firewall-v2/internal/wgconfig"
)

func managedTestKey(fill byte) string {
	value := make([]byte, 32)
	for index := range value {
		value[index] = fill
	}
	return base64.StdEncoding.EncodeToString(value)
}

func withManagedTestEnvironment(t *testing.T) (string, string) {
	t.Helper()
	oldDockerDaemon, oldDockerDropIn := managedDockerDaemon, managedDockerDropIn
	oldSystemdDir, oldNetworkGateState := managedSystemdDir, managedNetworkGateState
	oldAdoptionPlan := managedAdoptionPlan
	oldSetupRollbackAcquire := setupRollbackAcquire
	oldSetupRecoverySystem := setupRecoverySystem
	oldSetupRecoveryJournal := setupRecoveryJournal
	oldSetupBootStatus := setupBootStatus
	oldSetupBootHandoff := setupBootHandoff
	oldSetupBootHold := setupBootHold
	oldSetupDockerHold := setupDockerHold
	oldValues := []any{
		managedIntentPath, managedConfigPath, managedVPNPath, setupJournalPath,
		setupLockPath, managedStatusSock, managedControlSock, managedStateDB,
		managedLedger, managedGenerations, managedEnforcement, managedSysctl,
		managedStateRoot, managedRuntimeRoot, managedEUID, managedAPICall,
		managedTunnelUp, managedTunnelDown, managedTunnelStatus,
		managedChangeDir, managedChangeJournal, managedChangeOldIntent,
		managedChangeOldConfig, managedChangeNow, managedChangeTimeout,
	}
	t.Cleanup(func() {
		managedDockerDaemon = oldDockerDaemon
		managedDockerDropIn = oldDockerDropIn
		managedSystemdDir = oldSystemdDir
		managedNetworkGateState = oldNetworkGateState
		managedIntentPath = oldValues[0].(string)
		managedConfigPath = oldValues[1].(string)
		managedVPNPath = oldValues[2].(string)
		setupJournalPath = oldValues[3].(string)
		setupLockPath = oldValues[4].(string)
		managedStatusSock = oldValues[5].(string)
		managedControlSock = oldValues[6].(string)
		managedStateDB = oldValues[7].(string)
		managedLedger = oldValues[8].(string)
		managedGenerations = oldValues[9].(string)
		managedEnforcement = oldValues[10].(string)
		managedSysctl = oldValues[11].(string)
		managedStateRoot = oldValues[12].(string)
		managedRuntimeRoot = oldValues[13].(string)
		managedEUID = oldValues[14].(func() int)
		managedAPICall = oldValues[15].(func(context.Context, string, api.Request) (api.Response, error))
		managedTunnelUp = oldValues[16].(func(context.Context, routing.Config) error)
		managedTunnelDown = oldValues[17].(func(context.Context, routing.Config) error)
		managedTunnelStatus = oldValues[18].(func(context.Context, routing.Config) (map[string]any, error))
		managedChangeDir = oldValues[19].(string)
		managedChangeJournal = oldValues[20].(string)
		managedChangeOldIntent = oldValues[21].(string)
		managedChangeOldConfig = oldValues[22].(string)
		managedChangeNow = oldValues[23].(func() time.Time)
		managedChangeTimeout = oldValues[24].(time.Duration)
		managedAdoptionPlan = oldAdoptionPlan
		setupRollbackAcquire = oldSetupRollbackAcquire
		setupRecoverySystem = oldSetupRecoverySystem
		setupRecoveryJournal = oldSetupRecoveryJournal
		setupBootStatus = oldSetupBootStatus
		setupBootHandoff = oldSetupBootHandoff
		setupBootHold = oldSetupBootHold
		setupDockerHold = oldSetupDockerHold
	})

	root := t.TempDir()
	managedStateRoot = filepath.Join(root, "var/lib/nftfw")
	managedRuntimeRoot = filepath.Join(root, "run/nftfw")
	managedIntentPath = filepath.Join(root, "etc/nftfw/intent.toml")
	managedConfigPath = filepath.Join(root, "etc/nftfw/nftfw.toml")
	managedVPNPath = filepath.Join(root, "etc/wireguard/nftfw0.conf")
	setupJournalPath = filepath.Join(managedStateRoot, "setup/journal.json")
	setupLockPath = filepath.Join(managedRuntimeRoot, "setup.lock")
	managedStatusSock = filepath.Join(managedRuntimeRoot, "status.sock")
	managedControlSock = filepath.Join(managedRuntimeRoot, "control.sock")
	managedStateDB = filepath.Join(managedStateRoot, "generation-state/state.db")
	managedLedger = filepath.Join(managedStateRoot, "provenance-ledger.db")
	managedGenerations = filepath.Join(managedStateRoot, "generations")
	managedEnforcement = filepath.Join(managedStateRoot, "enforcement-enabled")
	managedSysctl = filepath.Join(root, "etc/sysctl.d/90-nftfw-managed.conf")
	managedDockerDaemon = filepath.Join(root, "etc/docker/daemon.json")
	managedDockerDropIn = filepath.Join(
		root, "etc/systemd/system/nftfwd.service.d/docker-access.conf",
	)
	managedSystemdDir = filepath.Join(root, "etc/systemd/system")
	managedNetworkGateState = func(context.Context) ([]string, error) {
		return []string{"ifup@.service", "networking.service"}, nil
	}
	managedChangeDir = filepath.Join(managedStateRoot, "managed-change")
	managedChangeJournal = filepath.Join(managedChangeDir, "journal.json")
	managedChangeOldIntent = filepath.Join(managedChangeDir, "old-intent.toml")
	managedChangeOldConfig = filepath.Join(managedChangeDir, "old-nftfw.toml")
	managedChangeNow = time.Now
	managedChangeTimeout = 2 * time.Minute
	managedEUID = func() int { return 0 }
	managedTunnelStatus = func(context.Context, routing.Config) (map[string]any, error) {
		return map[string]any{"active": true, "healthy": true, "interface": "nftfw0"}, nil
	}
	managedTunnelUp = func(context.Context, routing.Config) error { return nil }
	managedTunnelDown = func(context.Context, routing.Config) error { return nil }

	value := intent.Intent{
		Schema: intent.Schema, Managed: true, Uplink: "eth0",
		VPNInterface: intent.VPNInterface,
		LANNetworks:  []string{"192.168.1.0/24"}, ManagementTCP: []int{22},
		VPNAddresses: []string{"10.8.0.2/32"}, EndpointHost: "vpn.example.test",
		EndpointPort: 51820, BootstrapIPv4: []string{"198.51.100.8/32"},
		MTU: 1420, ResolverMode: "none", DisableIPv6: true,
	}
	intentData, err := value.Render()
	if err != nil {
		t.Fatal(err)
	}
	generated, err := value.Config()
	if err != nil {
		t.Fatal(err)
	}
	configData, err := intent.RenderConfig(generated)
	if err != nil {
		t.Fatal(err)
	}
	profileText := `[Interface]
PrivateKey = ` + managedTestKey(1) + `
Address = 10.8.0.2/32
[Peer]
PublicKey = ` + managedTestKey(2) + `
AllowedIPs = 0.0.0.0/0
Endpoint = vpn.example.test:51820
`
	profile, _, err := wgconfig.Parse([]byte(profileText))
	if err != nil {
		t.Fatal(err)
	}
	vpnData, err := profile.NormalizedWGQuick(intent.VPNInterface)
	if err != nil {
		t.Fatal(err)
	}
	for path, data := range map[string][]byte{
		managedIntentPath: intentData,
		managedConfigPath: configData,
		managedVPNPath:    vpnData,
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(managedRuntimeRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	producerPaths, err := netgate.DropInPaths(
		managedSystemdDir, []string{"ifup@.service", "networking.service"},
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range producerPaths {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(netgate.DropInData), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	source := filepath.Join(root, "provider.conf")
	if err := os.WriteFile(source, []byte(profileText), 0o600); err != nil {
		t.Fatal(err)
	}
	return root, source
}

type setupRecoveryFixture struct {
	committed   bool
	err         error
	rollbackErr error
	recoveryErr error
	finalizeErr error
	calls       []string
	onRollback  func(managedsetup.Journal)
	onRecovery  func(managedsetup.Journal)
	onFinalize  func(managedsetup.Journal)
}

func (f *setupRecoveryFixture) GenerationCommitted(_ context.Context, generation uint64) (bool, error) {
	f.calls = append(f.calls, "inspect:"+strconv.FormatUint(generation, 10))
	return f.committed, f.err
}

func (f *setupRecoveryFixture) Rollback(
	_ context.Context, _ managedsetup.Plan, journal managedsetup.Journal,
) error {
	f.calls = append(f.calls, "rollback:"+string(journal.Phase))
	if f.onRollback != nil {
		f.onRollback(journal)
	}
	return f.rollbackErr
}

func (f *setupRecoveryFixture) RecoverCommitted(
	_ context.Context, _ managedsetup.Plan, journal managedsetup.Journal,
) error {
	f.calls = append(f.calls, "recover:"+string(journal.Phase))
	if f.onRecovery != nil {
		f.onRecovery(journal)
	}
	return f.recoveryErr
}

func (f *setupRecoveryFixture) FinalizeBootRollback(
	_ context.Context, journal managedsetup.Journal,
) error {
	f.calls = append(f.calls, "finalize:"+strconv.FormatUint(journal.Generation, 10))
	if f.onFinalize != nil {
		f.onFinalize(journal)
	}
	return f.finalizeErr
}

type setupRecoveryJournalFixture struct {
	journal   managedsetup.Journal
	writes    []managedsetup.Journal
	failWrite int
}

func (s *setupRecoveryJournalFixture) Read() (managedsetup.Journal, error) {
	return s.journal, nil
}

func (s *setupRecoveryJournalFixture) Write(journal managedsetup.Journal) error {
	s.writes = append(s.writes, journal)
	if s.failWrite == len(s.writes) {
		return errors.New("injected journal write failure")
	}
	s.journal = journal
	return nil
}

func (s *setupRecoveryJournalFixture) Begin(journal managedsetup.Journal, _ string) error {
	return s.Write(journal)
}

func TestManagedMutationCommitDryRunNoOpAndRollback(t *testing.T) {
	_, _ = withManagedTestEnvironment(t)
	var calls []string
	managedAPICall = func(_ context.Context, _ string, request api.Request) (api.Response, error) {
		calls = append(calls, request.Op)
		switch request.Op {
		case "apply":
			return api.Response{OK: true, Data: reconcile.Result{Generation: 7}}, nil
		case "commit", "rollback":
			return api.Response{OK: true}, nil
		default:
			return api.Response{}, errors.New("unexpected")
		}
	}
	if err := changeManagedIntent("add public tcp", managedMutationOptions{Yes: true}, func(value *intent.Intent) error {
		return value.AddExposure("tcp", 443)
	}); err != nil {
		t.Fatal(err)
	}
	loaded, _, err := loadManagedIntent()
	if err != nil || !reflect.DeepEqual(loaded.PublicTCP, []int{443}) {
		t.Fatalf("managed change not persisted: %#v %v", loaded, err)
	}
	if strings.Join(calls, ",") != "apply,commit" {
		t.Fatalf("unexpected control calls: %v", calls)
	}

	before, _ := os.ReadFile(managedIntentPath)
	calls = nil
	if err := changeManagedIntent("add public udp", managedMutationOptions{DryRun: true}, func(value *intent.Intent) error {
		return value.AddExposure("udp", 53)
	}); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(managedIntentPath)
	if string(before) != string(after) || len(calls) != 0 {
		t.Fatal("dry run changed managed state")
	}

	if err := changeManagedIntent("add existing", managedMutationOptions{Yes: true}, func(value *intent.Intent) error {
		return value.AddExposure("tcp", 443)
	}); err != nil {
		t.Fatal(err)
	}

	managedAPICall = func(_ context.Context, _ string, request api.Request) (api.Response, error) {
		if request.Op == "apply" {
			return api.Response{}, errors.New("apply failed")
		}
		return api.Response{OK: true}, nil
	}
	before, _ = os.ReadFile(managedIntentPath)
	if err := changeManagedIntent("add public udp", managedMutationOptions{Yes: true}, func(value *intent.Intent) error {
		return value.AddExposure("udp", 53)
	}); err == nil {
		t.Fatal("apply failure was ignored")
	}
	after, _ = os.ReadFile(managedIntentPath)
	if string(before) != string(after) {
		t.Fatal("apply failure did not restore intent")
	}
}

func TestManagedCommandParsingAndReadViews(t *testing.T) {
	_, _ = withManagedTestEnvironment(t)
	operands, options, err := parseManagedMutationArgs([]string{"add", "tcp", "443", "--dry-run", "--yes", "--json"})
	if err != nil || strings.Join(operands, ",") != "add,tcp,443" ||
		!options.DryRun || !options.Yes || !options.JSON {
		t.Fatalf("managed options parse failed: %v %#v %v", operands, options, err)
	}
	for _, args := range [][]string{
		{"add", "--unknown"}, {"add", "--yes", "--yes"},
	} {
		if _, _, err := parseManagedMutationArgs(args); err == nil {
			t.Fatalf("invalid managed options accepted: %v", args)
		}
	}
	if ports, err := parsePorts([]string{"443", "80"}); err != nil || !reflect.DeepEqual(ports, []int{443, 80}) {
		t.Fatalf("port parsing failed: %v %v", ports, err)
	}
	for _, values := range [][]string{{"0"}, {"65536"}, {"80", "80"}, {"bad"}} {
		if _, err := parsePorts(values); err == nil {
			t.Fatalf("invalid ports accepted: %v", values)
		}
	}
	if displayPorts(nil) != "none" || displayPorts([]int{80, 443}) != "80,443" {
		t.Fatal("port display changed")
	}
	if err := exposureCommand([]string{"list"}); err != nil {
		t.Fatal(err)
	}
	if err := lanCommand([]string{"list", "--json"}); err != nil {
		t.Fatal(err)
	}
	if err := managedConfigShow([]string{"--effective", "--json"}); err != nil {
		t.Fatal(err)
	}
	for _, call := range []func() error{
		func() error { return exposureCommand([]string{"bad"}) },
		func() error { return lanCommand([]string{"bad"}) },
		func() error { return managedConfigShow(nil) },
	} {
		if err := call(); err == nil {
			t.Fatal("invalid managed view command accepted")
		}
	}
}

func TestExistingManagedSetupAndTunnelCommands(t *testing.T) {
	_, source := withManagedTestEnvironment(t)
	const hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	managedAPICall = func(_ context.Context, _ string, request api.Request) (api.Response, error) {
		if request.Op != "status" {
			return api.Response{}, errors.New("unexpected")
		}
		return api.Response{OK: true, Data: health.Snapshot{
			Schema: health.StatusSchema, Status: "HEALTHY", Active: true,
			PolicyMatch: true, KillSwitchEnforced: true,
			PolicyHash: hash, PolicyChecksum: hash, Managed: true,
		}}, nil
	}
	existing, summary, err := existingManagedSetup(context.Background(), source)
	if err != nil || !existing || summary.VPNInterface != "nftfw0" {
		t.Fatalf("healthy managed setup not recognized: %t %#v %v", existing, summary, err)
	}
	config, err := loadRoutingConfig()
	if err != nil || config.Interface != "nftfw0" {
		t.Fatalf("routing config load failed: %#v %v", config, err)
	}

	var operations []string
	managedTunnelStatus = func(context.Context, routing.Config) (map[string]any, error) {
		return map[string]any{"active": true, "healthy": false, "interface": "nftfw0"}, nil
	}
	managedTunnelDown = func(context.Context, routing.Config) error {
		operations = append(operations, "down")
		return nil
	}
	managedTunnelUp = func(context.Context, routing.Config) error {
		operations = append(operations, "up")
		return nil
	}
	if err := tunnelCommand([]string{"restart"}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(operations, ",") != "down,up" {
		t.Fatalf("unexpected tunnel restart operations: %v", operations)
	}
	if err := tunnelCommand([]string{"status", "--json"}); err != nil {
		t.Fatal(err)
	}
}

func TestManagedCommandsFailClosedOnNetworkProducerState(t *testing.T) {
	root, source := withManagedTestEnvironment(t)
	managedNetworkGateState = func(context.Context) ([]string, error) {
		return nil, errors.New("injected producer gate failure")
	}
	if err := managedConfigShow([]string{"--effective", "--json"}); err == nil ||
		err.Error() != "CONFIG_NETWORK_PRODUCER_STATE_INVALID" {
		t.Fatalf("config accepted invalid producer gate state: %v", err)
	}
	if err := managedBackupCommand([]string{
		"create", filepath.Join(root, "backups", "invalid-producer"), "--json",
	}); err == nil || err.Error() != "BACKUP_NETWORK_PRODUCER_STATE_INVALID" {
		t.Fatalf("backup accepted invalid producer gate state: %v", err)
	}
	const hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	managedAPICall = func(_ context.Context, _ string, request api.Request) (api.Response, error) {
		if request.Op != "status" {
			return api.Response{}, errors.New("unexpected")
		}
		return api.Response{OK: true, Data: health.Snapshot{
			Schema: health.StatusSchema, Status: "HEALTHY", Active: true,
			PolicyMatch: true, KillSwitchEnforced: true,
			PolicyHash: hash, PolicyChecksum: hash, Managed: true,
		}}, nil
	}
	if existing, _, err := existingManagedSetup(context.Background(), source); err == nil ||
		err.Error() != "SETUP_ALREADY_MANAGED_RECOVERY_REQUIRED" || existing {
		t.Fatalf("idempotent setup accepted invalid producer gate state: existing=%t err=%v", existing, err)
	}
}

func TestManagedSetupStatusRollbackAndUsageFailures(t *testing.T) {
	_, _ = withManagedTestEnvironment(t)
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	store := managedsetup.FileJournal{Path: setupJournalPath}
	if err := store.Write(managedsetup.Journal{
		Schema: "nftfw.setup-journal.v1", Transaction: "complete",
		Phase: managedsetup.PhaseComplete, Status: "complete",
		StartedAt: now, UpdatedAt: now, Deadline: now.Add(time.Minute),
		Generation: 7, Committed: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := setupCommand([]string{"status", "--json"}); err != nil {
		t.Fatal(err)
	}
	if err := setupRollbackCommand(nil); err != nil {
		t.Fatal(err)
	}
	for _, call := range []func() error{
		func() error { return setupCommand(nil) },
		func() error { return setupCommand([]string{"status", "bad"}) },
		func() error { return setupRollbackCommand([]string{"bad"}) },
		func() error { return tunnelCommand(nil) },
		func() error { return exposeCommand([]string{"bad"}) },
		func() error { return managedBackupCommand(nil) },
	} {
		if err := call(); err == nil {
			t.Fatal("invalid managed command accepted")
		}
	}
}

func TestExpiredSetupWatchdogDoesNotContendWithLiveTransaction(t *testing.T) {
	_, _ = withManagedTestEnvironment(t)
	store := managedsetup.FileJournal{Path: setupJournalPath}
	now := time.Now().UTC()
	journal := managedsetup.Journal{
		Schema: "nftfw.setup-journal.v1", Transaction: "foreground",
		Phase: managedsetup.PhaseRuntime, Status: "running",
		StartedAt: now.Add(-time.Hour), UpdatedAt: now, Deadline: now.Add(time.Hour),
		BackupDir: filepath.Join(managedStateRoot, "setup/backups/foreground"),
		Summary:   managedsetup.Summary{Schema: "nftfw.setup-plan.v1"},
	}
	if err := store.Write(journal); err != nil {
		t.Fatal(err)
	}
	release, err := acquireSetupLock()
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if err := setupRollbackCommand([]string{"--expired"}); err != nil {
		t.Fatalf("unexpired watchdog contended with foreground setup: %v", err)
	}
	journal.Deadline = now.Add(-time.Second)
	journal.UpdatedAt = now
	if err := store.Write(journal); err != nil {
		t.Fatal(err)
	}
	if err := setupRollbackCommand([]string{"--expired"}); err == nil ||
		err.Error() != "SETUP_ALREADY_RUNNING" {
		t.Fatalf("expired watchdog bypassed canonical lock: %v", err)
	}
}

func TestExpiredSetupWatchdogRevalidatesJournalAfterLock(t *testing.T) {
	_, _ = withManagedTestEnvironment(t)
	store := managedsetup.FileJournal{Path: setupJournalPath}
	now := time.Now().UTC()
	original := managedsetup.Journal{
		Schema: "nftfw.setup-journal.v1", Transaction: "expired-original",
		Phase: managedsetup.PhaseBackup, Status: "running",
		StartedAt: now.Add(-time.Hour), UpdatedAt: now, Deadline: now.Add(-time.Minute),
	}
	if err := store.Write(original); err != nil {
		t.Fatal(err)
	}
	setupRollbackAcquire = func() (func(), error) {
		replacement := original
		replacement.Transaction = "replacement"
		replacement.StartedAt = replacement.StartedAt.Add(time.Second)
		if err := store.Write(replacement); err != nil {
			return nil, err
		}
		return acquireSetupLock()
	}
	if err := setupRollbackCommand([]string{"--expired"}); err == nil ||
		err.Error() != "SETUP_JOURNAL_CHANGED" {
		t.Fatalf("replacement journal was not refused: %v", err)
	}
	replacement, err := store.Read()
	if err != nil || replacement.Status != "running" || replacement.Transaction != "replacement" {
		t.Fatalf("replacement journal was mutated: %#v %v", replacement, err)
	}
}

func TestExpiredSetupWatchdogRechecksDeadlineUnderLock(t *testing.T) {
	_, _ = withManagedTestEnvironment(t)
	store := managedsetup.FileJournal{Path: setupJournalPath}
	now := time.Now().UTC()
	journal := managedsetup.Journal{
		Schema: "nftfw.setup-journal.v1", Transaction: "same-transaction",
		Phase: managedsetup.PhaseBackup, Status: "running",
		StartedAt: now.Add(-time.Hour), UpdatedAt: now, Deadline: now.Add(-time.Minute),
	}
	if err := store.Write(journal); err != nil {
		t.Fatal(err)
	}
	setupRollbackAcquire = func() (func(), error) {
		journal.Deadline = now.Add(time.Hour)
		journal.UpdatedAt = now.Add(time.Second)
		if err := store.Write(journal); err != nil {
			return nil, err
		}
		return acquireSetupLock()
	}
	if err := setupRollbackCommand([]string{"--expired"}); err != nil {
		t.Fatalf("renewed same transaction was not rechecked under lock: %v", err)
	}
	current, err := store.Read()
	if err != nil || current.Status != "running" || !current.Deadline.Equal(journal.Deadline) {
		t.Fatalf("renewed journal was mutated: %#v %v", current, err)
	}
}

func TestSetupLockIsReleasedWhenOwnerProcessDies(t *testing.T) {
	if os.Getenv("NFTFW_SETUP_LOCK_OWNER_HELPER") == "1" {
		setupLockPath = os.Getenv("NFTFW_SETUP_LOCK_HELPER_PATH")
		release, err := acquireSetupLock()
		if err != nil {
			os.Exit(2)
		}
		defer release()
		if err := os.WriteFile(os.Getenv("NFTFW_SETUP_LOCK_HELPER_READY"), []byte("ready\n"), 0o600); err != nil {
			os.Exit(3)
		}
		time.Sleep(time.Minute)
		return
	}
	root, _ := withManagedTestEnvironment(t)
	ready := filepath.Join(root, "lock-owner-ready")
	command := exec.Command(os.Args[0], "-test.run=^TestSetupLockIsReleasedWhenOwnerProcessDies$", "-test.count=1")
	command.Env = []string{
		"NFTFW_SETUP_LOCK_OWNER_HELPER=1",
		"NFTFW_SETUP_LOCK_HELPER_PATH=" + setupLockPath,
		"NFTFW_SETUP_LOCK_HELPER_READY=" + ready,
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(5 * time.Second); ; {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			_ = command.Process.Kill()
			_ = command.Wait()
			t.Fatal("lock-owner helper did not become ready")
		}
		time.Sleep(time.Millisecond)
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err == nil {
		t.Fatal("killed lock-owner helper exited successfully")
	}
	now := time.Now().UTC()
	store := managedsetup.FileJournal{Path: setupJournalPath}
	if err := store.Write(managedsetup.Journal{
		Schema: "nftfw.setup-journal.v1", Transaction: "owner-died",
		Phase: managedsetup.PhaseBackup, Status: "running",
		StartedAt: now.Add(-time.Hour), UpdatedAt: now, Deadline: now.Add(-time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	if err := setupRollbackCommand([]string{"--expired"}); err != nil {
		t.Fatalf("dead owner left the kernel lock held: %v", err)
	}
	journal, err := store.Read()
	if err != nil || journal.Status != "rolled_back" {
		t.Fatalf("expired journal was not recovered after owner death: %#v %v", journal, err)
	}
}

func TestOutOfProcessSetupRollbackClassifiesEveryPostApplyPrecommitPhase(t *testing.T) {
	for _, phase := range []managedsetup.Phase{
		managedsetup.PhaseApply,
		managedsetup.PhaseTunnel,
		managedsetup.PhaseValidate,
		managedsetup.PhaseCommit,
	} {
		t.Run(string(phase), func(t *testing.T) {
			_, _ = withManagedTestEnvironment(t)
			fixture := &setupRecoveryFixture{}
			setupRecoverySystem = func() setupRecoveryExecutor { return fixture }
			now := time.Now().UTC()
			store := managedsetup.FileJournal{Path: setupJournalPath}
			if err := store.Write(managedsetup.Journal{
				Schema: "nftfw.setup-journal.v1", Transaction: "dead-" + string(phase),
				Phase: phase, Status: "running", StartedAt: now.Add(-time.Minute),
				UpdatedAt: now, Deadline: now.Add(time.Minute), Generation: 7,
				BackupDir: filepath.Join(managedStateRoot, "setup/backups/dead-"+string(phase)),
				Summary:   managedsetup.Summary{Schema: "nftfw.setup-plan.v1"},
			}); err != nil {
				t.Fatal(err)
			}
			if err := setupRollbackCommand(nil); err != nil {
				t.Fatalf("out-of-process recovery failed: %v", err)
			}
			wantCalls := "inspect:7,rollback:" + string(phase)
			if strings.Join(fixture.calls, ",") != wantCalls {
				t.Fatalf("recovery calls=%v want=%s", fixture.calls, wantCalls)
			}
			journal, err := store.Read()
			if err != nil || journal.Status != "rolled_back" || journal.Committed {
				t.Fatalf("uncommitted process-death journal not terminalized: %#v %v", journal, err)
			}
		})
	}
}

func TestInverseBootRollbackFinalizationPreservesOnlyUncommittedGeneration(t *testing.T) {
	for _, test := range []struct {
		name           string
		generation     uint64
		committed      bool
		wantGeneration uint64
	}{
		{name: "retained-first-setup-generation", generation: 7, wantGeneration: 7},
		{name: "pre-generation-rollback", generation: 0, wantGeneration: 0},
		{name: "committed-package-handoff", generation: 7, committed: true, wantGeneration: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, _ = withManagedTestEnvironment(t)
			now := time.Now().UTC()
			backup := filepath.Join(managedStateRoot, "setup/backups/inverse-boot-"+test.name)
			store := managedsetup.FileJournal{Path: setupJournalPath}
			journal := managedsetup.Journal{
				Schema: "nftfw.setup-journal.v1", Transaction: "inverse-boot-" + test.name,
				Phase: managedsetup.PhaseFailed, Status: "rollback_reboot_required",
				StartedAt: now.Add(-time.Minute), UpdatedAt: now, Deadline: now.Add(time.Minute),
				BackupDir: backup, Generation: test.generation, Committed: test.committed,
				Summary: managedsetup.Summary{
					Schema: "nftfw.setup-plan.v1", BootPolicy: managedsetup.ManagedBootPolicy,
				},
			}
			if err := store.Write(journal); err != nil {
				t.Fatal(err)
			}
			fixture := &setupRecoveryFixture{}
			setupRecoverySystem = func() setupRecoveryExecutor { return fixture }
			if err := setupRollbackCommand(nil); err != nil {
				t.Fatalf("inverse-boot rollback finalization failed: %v", err)
			}
			if strings.Join(fixture.calls, ",") != "finalize:"+strconv.FormatUint(test.generation, 10) {
				t.Fatalf("unexpected finalizer calls: %v", fixture.calls)
			}
			final, err := store.Read()
			if err != nil || final.Status != "rolled_back" || final.Phase != managedsetup.PhaseFailed ||
				final.Committed || final.Generation != test.wantGeneration || final.BackupDir != backup {
				t.Fatalf("invalid inverse-boot terminal lineage: %#v err=%v", final, err)
			}
			if err := validateSetupWatchdogJournal(final); err != nil {
				t.Fatalf("terminal inverse-boot journal was not valid: %v", err)
			}
		})
	}
}

func TestInverseBootRollbackFinalizerFailureCannotPublishTerminalState(t *testing.T) {
	_, _ = withManagedTestEnvironment(t)
	now := time.Now().UTC()
	store := managedsetup.FileJournal{Path: setupJournalPath}
	journal := managedsetup.Journal{
		Schema: "nftfw.setup-journal.v1", Transaction: "inverse-boot-finalizer-failure",
		Phase: managedsetup.PhaseFailed, Status: "rollback_reboot_required",
		StartedAt: now.Add(-time.Minute), UpdatedAt: now, Deadline: now.Add(time.Minute),
		BackupDir:  filepath.Join(managedStateRoot, "setup/backups/inverse-boot-finalizer-failure"),
		Generation: 7,
		Summary: managedsetup.Summary{
			Schema: "nftfw.setup-plan.v1", BootPolicy: managedsetup.ManagedBootPolicy,
		},
	}
	if err := store.Write(journal); err != nil {
		t.Fatal(err)
	}
	fixture := &setupRecoveryFixture{finalizeErr: errors.New("injected finalizer failure")}
	setupRecoverySystem = func() setupRecoveryExecutor { return fixture }
	if err := setupRollbackCommand(nil); err == nil || err.Error() != "SETUP_ROLLBACK_REBOOT_STILL_REQUIRED" {
		t.Fatalf("finalizer failure was not fail-closed: %v", err)
	}
	retained, err := store.Read()
	if err != nil || !reflect.DeepEqual(retained, journal) {
		t.Fatalf("finalizer failure changed durable state: %#v err=%v", retained, err)
	}
}

func TestInverseBootRollbackTerminalWriteFailureRetainsRebootState(t *testing.T) {
	_, _ = withManagedTestEnvironment(t)
	now := time.Now().UTC()
	journal := managedsetup.Journal{
		Schema: "nftfw.setup-journal.v1", Transaction: "inverse-boot-write-failure",
		Phase: managedsetup.PhaseFailed, Status: "rollback_reboot_required",
		StartedAt: now.Add(-time.Minute), UpdatedAt: now, Deadline: now.Add(time.Minute),
		BackupDir:  filepath.Join(managedStateRoot, "setup/backups/inverse-boot-write-failure"),
		Generation: 7,
		Summary: managedsetup.Summary{
			Schema: "nftfw.setup-plan.v1", BootPolicy: managedsetup.ManagedBootPolicy,
		},
	}
	store := &setupRecoveryJournalFixture{journal: journal, failWrite: 1}
	setupRecoveryJournal = func() managedsetup.JournalStore { return store }
	fixture := &setupRecoveryFixture{}
	setupRecoverySystem = func() setupRecoveryExecutor { return fixture }
	if err := setupRollbackCommand(nil); err == nil || err.Error() != "SETUP_RECOVERY_RESULT_WRITE_FAILED" {
		t.Fatalf("terminal write failure was not fail-closed: %v", err)
	}
	if !reflect.DeepEqual(store.journal, journal) || len(store.writes) != 1 ||
		store.writes[0].Status != "rolled_back" || store.writes[0].Generation != journal.Generation {
		t.Fatalf("terminal write failure published or changed lineage: journal=%#v writes=%#v", store.journal, store.writes)
	}
}

func TestOutOfProcessSetupRollbackRecoversCommitJournalGapForward(t *testing.T) {
	_, _ = withManagedTestEnvironment(t)
	fixture := &setupRecoveryFixture{committed: true}
	setupRecoverySystem = func() setupRecoveryExecutor { return fixture }
	now := time.Now().UTC()
	store := managedsetup.FileJournal{Path: setupJournalPath}
	if err := store.Write(managedsetup.Journal{
		Schema: "nftfw.setup-journal.v1", Transaction: "dead-after-commit",
		Phase: managedsetup.PhaseCommit, Status: "running",
		StartedAt: now.Add(-time.Minute), UpdatedAt: now, Deadline: now.Add(time.Minute),
		Generation: 7,
		BackupDir:  filepath.Join(managedStateRoot, "setup/backups/dead-after-commit"),
		Summary:    managedsetup.Summary{Schema: "nftfw.setup-plan.v1"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := setupRollbackCommand(nil); err != nil {
		t.Fatalf("commit-gap recovery failed: %v", err)
	}
	if strings.Join(fixture.calls, ",") != "inspect:7,recover:commit" {
		t.Fatalf("commit-gap recovery calls=%v", fixture.calls)
	}
	journal, err := store.Read()
	if err != nil || journal.Status != "complete" || !journal.Committed {
		t.Fatalf("committed process-death journal not recovered forward: %#v %v", journal, err)
	}
}

func TestOutOfProcessRecoveryPublishesTransitionsBeforeMutation(t *testing.T) {
	for _, test := range []struct {
		name       string
		committed  bool
		transition string
		terminal   string
	}{
		{name: "rollback", transition: "rolling_back", terminal: "rolled_back"},
		{name: "committed", committed: true, transition: "recovering_committed", terminal: "complete"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, _ = withManagedTestEnvironment(t)
			now := time.Now().UTC()
			store := &setupRecoveryJournalFixture{journal: managedsetup.Journal{
				Schema: "nftfw.setup-journal.v1", Transaction: "transition-" + test.name,
				Phase: managedsetup.PhaseValidate, Status: "running",
				StartedAt: now.Add(-time.Minute), UpdatedAt: now, Deadline: now.Add(time.Minute),
				Generation: 7,
				BackupDir:  filepath.Join(managedStateRoot, "setup/backups/transition-"+test.name),
				Summary:    managedsetup.Summary{Schema: "nftfw.setup-plan.v1"},
			}}
			setupRecoveryJournal = func() managedsetup.JournalStore { return store }
			fixture := &setupRecoveryFixture{committed: test.committed}
			assertTransition := func(journal managedsetup.Journal) {
				if len(store.writes) != 1 || store.journal.Status != test.transition ||
					store.journal.Phase != managedsetup.PhaseValidate || journal.Phase != managedsetup.PhaseValidate {
					t.Fatalf("recovery mutation preceded its durable origin transition: writes=%#v journal=%#v", store.writes, journal)
				}
			}
			fixture.onRollback = assertTransition
			fixture.onRecovery = assertTransition
			setupRecoverySystem = func() setupRecoveryExecutor { return fixture }
			if err := setupRollbackCommand(nil); err != nil {
				t.Fatal(err)
			}
			if len(store.writes) != 2 || store.journal.Status != test.terminal {
				t.Fatalf("recovery result was not durable: writes=%#v final=%#v", store.writes, store.journal)
			}
		})
	}
}

func TestOutOfProcessRecoveryTransitionWriteFailureDoesNotMutate(t *testing.T) {
	_, _ = withManagedTestEnvironment(t)
	now := time.Now().UTC()
	store := &setupRecoveryJournalFixture{
		failWrite: 1,
		journal: managedsetup.Journal{
			Schema: "nftfw.setup-journal.v1", Transaction: "transition-write-failure",
			Phase: managedsetup.PhaseRuntime, Status: "running",
			StartedAt: now.Add(-time.Minute), UpdatedAt: now, Deadline: now.Add(time.Minute),
			BackupDir: filepath.Join(managedStateRoot, "setup/backups/transition-write-failure"),
			Summary:   managedsetup.Summary{Schema: "nftfw.setup-plan.v1"},
		},
	}
	setupRecoveryJournal = func() managedsetup.JournalStore { return store }
	fixture := &setupRecoveryFixture{}
	setupRecoverySystem = func() setupRecoveryExecutor { return fixture }
	err := setupRollbackCommand(nil)
	if err == nil || err.Error() != "SETUP_RECOVERY_TRANSITION_WRITE_FAILED" {
		t.Fatalf("transition write failure=%v", err)
	}
	if len(fixture.calls) != 0 {
		t.Fatalf("recovery mutated before transition publication: %v", fixture.calls)
	}
}

func TestOutOfProcessRecoveryFailureIsRedactedAndRetryable(t *testing.T) {
	_, _ = withManagedTestEnvironment(t)
	now := time.Now().UTC()
	store := managedsetup.FileJournal{Path: setupJournalPath}
	if err := store.Write(managedsetup.Journal{
		Schema: "nftfw.setup-journal.v1", Transaction: "retry-rollback",
		Phase: managedsetup.PhaseValidate, Status: "running",
		StartedAt: now.Add(-time.Minute), UpdatedAt: now, Deadline: now.Add(time.Minute),
		Generation: 7,
		BackupDir:  filepath.Join(managedStateRoot, "setup/backups/retry-rollback"),
		Summary:    managedsetup.Summary{Schema: "nftfw.setup-plan.v1"},
	}); err != nil {
		t.Fatal(err)
	}
	fixture := &setupRecoveryFixture{rollbackErr: errors.New("provider secret must never reach the journal")}
	setupRecoverySystem = func() setupRecoveryExecutor { return fixture }
	if err := setupRollbackCommand(nil); err == nil || err.Error() != "SETUP_ROLLBACK_FAILED" {
		t.Fatalf("rollback failure=%v", err)
	}
	failed, err := store.Read()
	if err != nil || failed.Status != "rollback_failed" ||
		failed.Phase != managedsetup.PhaseValidate || failed.ErrorCode != "SETUP_RECOVERY_FAILED" {
		t.Fatalf("rollback failure evidence invalid: %#v %v", failed, err)
	}

	fixture.calls = nil
	fixture.rollbackErr = nil
	fixture.err = errors.New("known uncommitted retry must not re-inspect")
	if err := setupRollbackCommand(nil); err != nil {
		t.Fatalf("rollback retry failed: %v", err)
	}
	if strings.Join(fixture.calls, ",") != "rollback:validate" {
		t.Fatalf("known uncommitted retry was reclassified: %v", fixture.calls)
	}
	final, err := store.Read()
	if err != nil || final.Status != "rolled_back" || final.Phase != managedsetup.PhaseFailed {
		t.Fatalf("rollback retry not terminal: %#v %v", final, err)
	}
}

func TestOutOfProcessCommittedRecoveryFailureIsRetryable(t *testing.T) {
	_, _ = withManagedTestEnvironment(t)
	now := time.Now().UTC()
	store := managedsetup.FileJournal{Path: setupJournalPath}
	if err := store.Write(managedsetup.Journal{
		Schema: "nftfw.setup-journal.v1", Transaction: "retry-committed",
		Phase: managedsetup.PhaseCommit, Status: "recovering_committed",
		StartedAt: now.Add(-time.Minute), UpdatedAt: now, Deadline: now.Add(time.Minute),
		Generation: 7, Committed: true,
		BackupDir: filepath.Join(managedStateRoot, "setup/backups/retry-committed"),
		Summary:   managedsetup.Summary{Schema: "nftfw.setup-plan.v1"},
	}); err != nil {
		t.Fatal(err)
	}
	fixture := &setupRecoveryFixture{recoveryErr: errors.New("SETUP_BOOT_ENABLE_FAILED")}
	setupRecoverySystem = func() setupRecoveryExecutor { return fixture }
	if err := setupRollbackCommand(nil); err == nil || err.Error() != "SETUP_COMMITTED_RECOVERY_FAILED" {
		t.Fatalf("committed recovery failure=%v", err)
	}
	failed, err := store.Read()
	if err != nil || failed.Status != "committed_recovery_failed" || !failed.Committed ||
		failed.Phase != managedsetup.PhaseCommit || failed.ErrorCode != "SETUP_BOOT_ENABLE_FAILED" {
		t.Fatalf("committed recovery evidence invalid: %#v %v", failed, err)
	}
	fixture.calls = nil
	fixture.recoveryErr = nil
	if err := setupRollbackCommand(nil); err != nil {
		t.Fatalf("committed recovery retry failed: %v", err)
	}
	if strings.Join(fixture.calls, ",") != "recover:commit" {
		t.Fatalf("committed recovery retry crossed classification: %v", fixture.calls)
	}
}

func TestSetupWatchdogRejectsMalformedRecoveryStateBeforeLock(t *testing.T) {
	_, _ = withManagedTestEnvironment(t)
	store := managedsetup.FileJournal{Path: setupJournalPath}
	now := time.Now().UTC()
	journal := managedsetup.Journal{
		Schema: "nftfw.setup-journal.v1", Transaction: "invalid",
		Phase: managedsetup.PhaseRuntime, Status: "running",
		StartedAt: now, UpdatedAt: now, Deadline: now.Add(time.Hour),
	}
	if err := store.Write(journal); err != nil {
		t.Fatal(err)
	}
	called := false
	setupRollbackAcquire = func() (func(), error) {
		called = true
		return acquireSetupLock()
	}
	if err := setupRollbackCommand([]string{"--expired"}); err == nil ||
		err.Error() != "SETUP_JOURNAL_STATE_INVALID" {
		t.Fatalf("invalid recovery evidence accepted: %v", err)
	}
	if called {
		t.Fatal("invalid unexpired journal acquired the setup lock")
	}
}

func TestSetupRecoveryJournalTransitionValidation(t *testing.T) {
	now := time.Now().UTC()
	base := managedsetup.Journal{
		Schema: "nftfw.setup-journal.v1", Transaction: "transition-validation",
		StartedAt: now.Add(-time.Minute), UpdatedAt: now, Deadline: now.Add(time.Minute),
		Generation: 7, BackupDir: "/var/lib/nftfw/setup/backups/transition-validation",
		Summary: managedsetup.Summary{Schema: "nftfw.setup-plan.v1"},
	}
	for _, valid := range []managedsetup.Journal{
		func() managedsetup.Journal {
			j := base
			j.Phase, j.Status, j.Generation = managedsetup.PhaseBootPrep, "reboot_required", 0
			return j
		}(),
		func() managedsetup.Journal {
			j := base
			j.Phase, j.Status, j.Generation = managedsetup.PhaseBootPrep, "resume_ready", 0
			return j
		}(),
		func() managedsetup.Journal {
			j := base
			j.Phase, j.Status = managedsetup.PhaseValidate, "rolling_back"
			return j
		}(),
		func() managedsetup.Journal {
			j := base
			j.Phase, j.Status = managedsetup.PhaseFailed, "rollback_failed"
			return j
		}(),
		func() managedsetup.Journal {
			j := base
			j.Phase, j.Status = managedsetup.PhaseCommit, "commit_state_unknown"
			return j
		}(),
		func() managedsetup.Journal {
			j := base
			j.Phase, j.Status, j.Committed = managedsetup.PhaseBoot, "recovering_committed", true
			return j
		}(),
		func() managedsetup.Journal {
			j := base
			j.Phase, j.Status, j.Committed = managedsetup.PhaseFinalize, "committed_recovery_failed", true
			return j
		}(),
		func() managedsetup.Journal {
			j := base
			j.Phase, j.Status, j.Committed = managedsetup.PhaseFailed, "rollback_reboot_required", true
			return j
		}(),
	} {
		if err := validateSetupWatchdogJournal(valid); err != nil {
			t.Fatalf("valid recovery transition rejected: %#v %v", valid, err)
		}
	}
	for _, invalid := range []managedsetup.Journal{
		func() managedsetup.Journal {
			j := base
			j.Phase, j.Status = managedsetup.PhaseHandoff, "rolling_back"
			return j
		}(),
		func() managedsetup.Journal {
			j := base
			j.Phase, j.Status = managedsetup.PhaseValidate, "recovering_committed"
			j.Committed = true
			return j
		}(),
		func() managedsetup.Journal {
			j := base
			j.Phase, j.Status = managedsetup.PhaseRuntime, "commit_state_unknown"
			return j
		}(),
		func() managedsetup.Journal {
			j := base
			j.Phase, j.Status = managedsetup.PhaseComplete, "running"
			return j
		}(),
	} {
		if err := validateSetupWatchdogJournal(invalid); err == nil || err.Error() != "SETUP_JOURNAL_STATE_INVALID" {
			t.Fatalf("invalid recovery transition accepted: %#v err=%v", invalid, err)
		}
	}
}

func TestSetupBootStatusIsRedactedAndReportsResumeReady(t *testing.T) {
	_, _ = withManagedTestEnvironment(t)
	now := time.Now().UTC()
	journal := managedsetup.Journal{
		Schema: "nftfw.setup-journal.v1", Transaction: "boot-status",
		Phase: managedsetup.PhaseBootPrep, Status: "reboot_required",
		StartedAt: now, UpdatedAt: now, Deadline: now.Add(time.Minute),
		BackupDir: "/private/boot/identity",
		Summary: managedsetup.Summary{
			Schema: "nftfw.setup-plan.v1", BootPolicy: managedsetup.ManagedBootPolicy,
		},
	}
	if err := (managedsetup.FileJournal{Path: setupJournalPath}).Write(journal); err != nil {
		t.Fatal(err)
	}
	setupBootStatus = func(context.Context, managedsetup.Journal) (string, error) {
		return "resume_ready", nil
	}
	var commandErr error
	output := captureManagedOutput(t, func() {
		commandErr = setupCommand([]string{"status", "--json"})
	})
	if commandErr != nil || !strings.Contains(output, `"status": "resume_ready"`) {
		t.Fatalf("resume-ready status missing: %v %s", commandErr, output)
	}
	for _, secret := range []string{"/private/boot/identity", "cmdline", "disk_uuid", "admin_argument"} {
		if strings.Contains(output, secret) {
			t.Fatalf("setup status leaked %q: %s", secret, output)
		}
	}
}

func TestSetupBootStatusFailsClosedOnInvalidProof(t *testing.T) {
	_, _ = withManagedTestEnvironment(t)
	now := time.Now().UTC()
	journal := managedsetup.Journal{
		Schema: "nftfw.setup-journal.v1", Transaction: "boot-status-invalid",
		Phase: managedsetup.PhaseBootPrep, Status: "reboot_required",
		StartedAt: now, UpdatedAt: now, Deadline: now.Add(time.Minute),
		BackupDir: "/private/boot/identity",
		Summary:   managedsetup.Summary{Schema: "nftfw.setup-plan.v1", BootPolicy: managedsetup.ManagedBootPolicy},
	}
	if err := (managedsetup.FileJournal{Path: setupJournalPath}).Write(journal); err != nil {
		t.Fatal(err)
	}
	setupBootStatus = func(context.Context, managedsetup.Journal) (string, error) {
		return "", errors.New("private detail /boot/secret")
	}
	err := setupCommand([]string{"status", "--json"})
	if err == nil || err.Error() != "SETUP_BOOT_STATUS_INVALID" || strings.Contains(err.Error(), "/boot/secret") {
		t.Fatalf("invalid boot status was not redacted and refused: %v", err)
	}
}

func TestSetupTransientHoldCommandsAreExactAndRootOnly(t *testing.T) {
	_, _ = withManagedTestEnvironment(t)
	bootCalls, dockerCalls := 0, 0
	setupBootHold = func(_ context.Context, store managedsetup.JournalStore) error {
		bootCalls++
		if _, ok := store.(managedsetup.FileJournal); !ok {
			t.Fatalf("boot hold did not receive the canonical journal store: %T", store)
		}
		return nil
	}
	setupDockerHold = func(context.Context) error {
		dockerCalls++
		return nil
	}
	if err := setupCommand([]string{"boot-hold"}); err != nil {
		t.Fatal(err)
	}
	if err := setupCommand([]string{"docker-hold"}); err != nil {
		t.Fatal(err)
	}
	if bootCalls != 1 || dockerCalls != 1 {
		t.Fatalf("transient hold calls boot=%d docker=%d", bootCalls, dockerCalls)
	}
	for _, args := range [][]string{{"boot-hold", "extra"}, {"docker-hold", "extra"}} {
		if err := setupCommand(args); err == nil {
			t.Fatalf("hidden hold accepted extra arguments: %v", args)
		}
	}
	managedEUID = func() int { return 1000 }
	for _, args := range [][]string{{"boot-hold"}, {"docker-hold"}} {
		if err := setupCommand(args); err == nil {
			t.Fatalf("non-root hidden hold was accepted: %v", args)
		}
	}
	if bootCalls != 1 || dockerCalls != 1 {
		t.Fatal("refused hidden hold crossed its execution boundary")
	}
}

func TestSetupPackageUpgradePreflightRefusesActiveBootTransaction(t *testing.T) {
	_, _ = withManagedTestEnvironment(t)
	now := time.Now().UTC()
	store := managedsetup.FileJournal{Path: setupJournalPath}
	journal := managedsetup.Journal{
		Schema: "nftfw.setup-journal.v1", Transaction: "package-upgrade-preflight",
		Phase: managedsetup.PhaseComplete, Status: "complete",
		StartedAt: now.Add(-time.Minute), UpdatedAt: now, Deadline: now.Add(time.Minute),
		BackupDir:  "/var/lib/nftfw/setup/backups/package-upgrade-preflight",
		Generation: 7, Committed: true,
		Summary: managedsetup.Summary{
			Schema: "nftfw.setup-plan.v1", BootPolicy: managedsetup.ManagedBootPolicy,
		},
	}
	if err := store.Write(journal); err != nil {
		t.Fatal(err)
	}
	if err := setupCommand([]string{"package-upgrade-preflight"}); err != nil {
		t.Fatalf("terminal managed boot state blocked an inert package upgrade: %v", err)
	}
	journal.Phase, journal.Status, journal.Generation, journal.Committed =
		managedsetup.PhaseBootPrep, "reboot_required", 0, false
	if err := store.Write(journal); err != nil {
		t.Fatal(err)
	}
	if err := setupCommand([]string{"package-upgrade-preflight"}); err == nil ||
		err.Error() != "SETUP_PACKAGE_UPGRADE_BOOT_TRANSACTION_ACTIVE" {
		t.Fatalf("pending reboot transaction allowed package replacement: %v", err)
	}
	journal.Phase, journal.Status, journal.Generation, journal.Committed =
		managedsetup.PhaseComplete, "complete", 7, true
	if err := store.Write(journal); err != nil {
		t.Fatal(err)
	}
	release, err := acquireSetupLock()
	if err != nil {
		t.Fatal(err)
	}
	if err := setupCommand([]string{"package-upgrade-preflight"}); err == nil ||
		err.Error() != "SETUP_PACKAGE_UPGRADE_BOOT_TRANSACTION_ACTIVE" {
		t.Fatalf("concurrent setup owner allowed package replacement: %v", err)
	}
	release()
	managedEUID = func() int { return 1000 }
	if err := setupCommand([]string{"package-upgrade-preflight"}); err == nil {
		t.Fatal("non-root package upgrade preflight was accepted")
	}
}

func TestSetupPackageBootHandoffPublishesRollbackRebootState(t *testing.T) {
	_, _ = withManagedTestEnvironment(t)
	now := time.Now().UTC()
	store := managedsetup.FileJournal{Path: setupJournalPath}
	journal := managedsetup.Journal{
		Schema: "nftfw.setup-journal.v1", Transaction: "boot-handoff",
		Phase: managedsetup.PhaseComplete, Status: "complete",
		StartedAt: now, UpdatedAt: now, Deadline: now.Add(time.Minute),
		BackupDir: "/var/lib/nftfw/setup/backups/boot-handoff", Generation: 7, Committed: true,
		Summary: managedsetup.Summary{
			Schema: "nftfw.setup-plan.v1", BootPolicy: managedsetup.ManagedBootPolicy,
		},
	}
	if err := store.Write(journal); err != nil {
		t.Fatal(err)
	}
	called := 0
	setupBootHandoff = func(context.Context, managedsetup.Journal) (bool, error) {
		called++
		return true, nil
	}
	if err := setupBootHandoffCommand([]string{"--package-remove"}); err != nil {
		t.Fatal(err)
	}
	updated, err := store.Read()
	if err != nil || called != 1 || updated.Status != "rollback_reboot_required" ||
		updated.Phase != managedsetup.PhaseFailed || !updated.Committed {
		t.Fatalf("package handoff state invalid: %#v called=%d err=%v", updated, called, err)
	}
	if err := validateSetupWatchdogJournal(updated); err != nil {
		t.Fatalf("package handoff journal was not a valid explicit state: %v", err)
	}
}

func TestSetupPackageBootHandoffWithoutRebootDoesNotPublishRetryGeneration(t *testing.T) {
	for _, test := range []struct {
		name      string
		phase     managedsetup.Phase
		status    string
		committed bool
	}{
		{name: "committed-install", phase: managedsetup.PhaseComplete, status: "complete", committed: true},
		{name: "failed-setup", phase: managedsetup.PhaseFailed, status: "rollback_reboot_required"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, _ = withManagedTestEnvironment(t)
			now := time.Now().UTC()
			store := managedsetup.FileJournal{Path: setupJournalPath}
			journal := managedsetup.Journal{
				Schema: "nftfw.setup-journal.v1", Transaction: "boot-handoff-no-reboot-" + test.name,
				Phase: test.phase, Status: test.status,
				StartedAt: now, UpdatedAt: now, Deadline: now.Add(time.Minute),
				BackupDir:  filepath.Join(managedStateRoot, "setup/backups/boot-handoff-no-reboot-"+test.name),
				Generation: 7, Committed: test.committed,
				Summary: managedsetup.Summary{
					Schema: "nftfw.setup-plan.v1", BootPolicy: managedsetup.ManagedBootPolicy,
				},
			}
			if err := store.Write(journal); err != nil {
				t.Fatal(err)
			}
			setupBootHandoff = func(context.Context, managedsetup.Journal) (bool, error) {
				return false, nil
			}
			if err := setupBootHandoffCommand([]string{"--package-remove"}); err != nil {
				t.Fatal(err)
			}
			updated, err := store.Read()
			if err != nil || updated.Status != "rolled_back" || updated.Phase != managedsetup.PhaseFailed ||
				updated.Committed || updated.Generation != 0 {
				t.Fatalf("package-only handoff published retry lineage: %#v err=%v", updated, err)
			}
		})
	}
}

func TestSetupAdoptIsExplicitDryRunOnlyAndRedactsFailures(t *testing.T) {
	_, source := withManagedTestEnvironment(t)
	calls := 0
	managedAdoptionPlan = func(ctx context.Context, path string) (adoption.Plan, error) {
		calls++
		if _, bounded := ctx.Deadline(); !bounded {
			t.Fatal("adoption inspection context is unbounded")
		}
		if path != source {
			t.Fatalf("unexpected profile path: %q", path)
		}
		return adoption.Plan{
			Schema: adoption.Schema, Status: "READY_FOR_SEPARATE_LIVE_PLAN",
			InstalledVersion: "2.0.3", CurrentMode: "advanced", TargetMode: "managed",
			State:            adoption.StateSummary{Schema: 6, Generation: 9},
			Network:          adoption.NetworkSummary{Uplink: "verified-single-ipv4", Resolver: "none", IPv6Mode: "disabled"},
			Docker:           adoption.DockerSummary{Topology: "absent"},
			LiveStateChanged: false, RollbackRequired: false,
			NextStep: "prepare a separate plan", DetailedLog: "sudo journalctl -u nftfwd",
		}, nil
	}
	if err := setupCommand([]string{"adopt", "--vpn", source, "--dry-run"}); err != nil {
		t.Fatal(err)
	}
	if err := setupCommand([]string{"adopt", "--vpn", source, "--dry-run", "--json"}); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("planner calls=%d", calls)
	}
	if err := setupCommand([]string{"adopt", "--vpn", source}); err == nil ||
		!strings.Contains(err.Error(), "ADOPTION_EXECUTION_REQUIRES_SEPARATE_LIVE_PLAN") || calls != 2 {
		t.Fatalf("adoption execution boundary failed: calls=%d err=%v", calls, err)
	}
	managedEUID = func() int { return 1000 }
	if err := setupCommand([]string{"adopt", "--vpn", source, "--dry-run"}); err == nil ||
		!strings.Contains(err.Error(), "ADOPTION_REQUIRES_ROOT") || calls != 2 {
		t.Fatalf("adoption root boundary failed: calls=%d err=%v", calls, err)
	}
	managedEUID = func() int { return 0 }
	managedAdoptionPlan = func(context.Context, string) (adoption.Plan, error) {
		return adoption.Plan{}, errors.New("private-key-material vpn.example.test 198.51.100.8")
	}
	err := setupCommand([]string{"adopt", "--vpn", source, "--dry-run"})
	if err == nil || !strings.Contains(err.Error(), "ADOPTION_INSPECTION_FAILED") ||
		strings.Contains(err.Error(), "private-key-material") || strings.Contains(err.Error(), "vpn.example.test") ||
		strings.Contains(err.Error(), "198.51.100.8") {
		t.Fatalf("unsafe adoption error: %v", err)
	}
}

func TestSetupAdoptGrammarCannotFallThroughToCleanSetup(t *testing.T) {
	_, source := withManagedTestEnvironment(t)
	for _, args := range [][]string{
		{"adopt"},
		{"adopt", "--vpn", source},
		{"adopt", "--vpn", source, "--dry-run", "--yes"},
		{"adopt", "--vpn", source, "--dry-run", "extra"},
		{"unknown", "--vpn", source},
		{"adopt", "--unknown=private-key-material", "--vpn", source, "--dry-run"},
	} {
		if err := setupCommand(args); err == nil || strings.Contains(err.Error(), "private-key-material") {
			t.Fatalf("invalid setup grammar accepted: %v", args)
		} else if args[0] == "adopt" && (!strings.Contains(err.Error(), "live state changed: NO") ||
			!strings.Contains(err.Error(), "rollback required: NO")) {
			t.Fatalf("adoption usage error is not actionable: %v", err)
		}
	}
}

func TestManagedMutationCommandsAndTunnelNoOps(t *testing.T) {
	_, _ = withManagedTestEnvironment(t)
	nextGeneration := uint64(10)
	managedAPICall = func(_ context.Context, _ string, request api.Request) (api.Response, error) {
		switch request.Op {
		case "apply":
			nextGeneration++
			return api.Response{OK: true, Data: reconcile.Result{Generation: nextGeneration}}, nil
		case "commit", "rollback":
			return api.Response{OK: true}, nil
		default:
			return api.Response{}, errors.New("unexpected operation")
		}
	}
	for _, command := range []func() error{
		func() error { return exposeCommand([]string{"add", "tcp", "443", "--yes", "--json"}) },
		func() error { return exposeCommand([]string{"add", "udp", "53", "--dry-run"}) },
		func() error { return exposeCommand([]string{"remove", "tcp", "443", "--yes"}) },
		func() error { return lanCommand([]string{"allow", "tcp", "8096", "--yes", "--json"}) },
		func() error { return lanCommand([]string{"allow", "udp", "1900", "--dry-run", "--json"}) },
		func() error { return lanCommand([]string{"deny", "tcp", "8096", "--yes"}) },
		func() error { return managedConfigShow([]string{"--effective"}) },
		func() error { return exposureCommand([]string{"list", "--json"}) },
		func() error { return lanCommand([]string{"list"}) },
	} {
		if err := command(); err != nil {
			t.Fatal(err)
		}
	}

	var upCalls, downCalls int
	managedTunnelStatus = func(context.Context, routing.Config) (map[string]any, error) {
		return map[string]any{"active": true, "healthy": true, "interface": "nftfw0"}, nil
	}
	managedTunnelUp = func(context.Context, routing.Config) error {
		upCalls++
		return nil
	}
	managedTunnelDown = func(context.Context, routing.Config) error {
		downCalls++
		return nil
	}
	if err := tunnelCommand([]string{"up"}); err != nil || upCalls != 0 {
		t.Fatalf("healthy tunnel was restarted: calls=%d err=%v", upCalls, err)
	}
	if err := tunnelCommand([]string{"down"}); err != nil || downCalls != 1 {
		t.Fatalf("active tunnel was not stopped: calls=%d err=%v", downCalls, err)
	}
	managedTunnelStatus = func(context.Context, routing.Config) (map[string]any, error) {
		return map[string]any{"active": false, "healthy": false, "interface": "nftfw0"}, nil
	}
	if err := tunnelCommand([]string{"down"}); err != nil || downCalls != 1 {
		t.Fatalf("inactive tunnel was stopped again: calls=%d err=%v", downCalls, err)
	}
	if err := tunnelCommand([]string{"up"}); err != nil || upCalls != 1 {
		t.Fatalf("inactive tunnel was not started: calls=%d err=%v", upCalls, err)
	}
}

func TestManagedBackupCreateVerifyAndIdempotentSetup(t *testing.T) {
	root, source := withManagedTestEnvironment(t)
	ctx := context.Background()
	store, err := state.Open(ctx, managedStateDB)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	ledger, err := provenance.Open(ctx, managedLedger)
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Reserve(ctx, []provenance.Assignment{
		{Name: "eth0", ID: 1}, {Name: "nftfw0", ID: 2},
	}); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(managedGenerations, 0o700); err != nil {
		t.Fatal(err)
	}
	backupParent := filepath.Join(root, "backups")
	if err := os.MkdirAll(backupParent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(backupParent, 0o700); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(backupParent, "operator-backup")
	if err := managedBackupCommand([]string{"create", backup, "--json"}); err != nil {
		t.Fatal(err)
	}
	if err := managedBackupCommand([]string{"verify", backup}); err != nil {
		t.Fatal(err)
	}

	digest := strings.Repeat("a", 64)
	managedAPICall = func(_ context.Context, _ string, request api.Request) (api.Response, error) {
		if request.Op != "status" {
			return api.Response{}, errors.New("unexpected")
		}
		return api.Response{OK: true, Data: health.Snapshot{
			Schema: health.StatusSchema, Status: "HEALTHY", Active: true,
			PolicyMatch: true, KillSwitchEnforced: true,
			PolicyHash: digest, PolicyChecksum: digest, Managed: true,
		}}, nil
	}
	managedTunnelStatus = func(context.Context, routing.Config) (map[string]any, error) {
		return map[string]any{"active": true, "healthy": true, "interface": "nftfw0"}, nil
	}
	if err := setupCommand([]string{"--vpn", source, "--yes", "--json"}); err != nil {
		t.Fatal(err)
	}
}

func TestManagedPermissionAndFileSafetyFailures(t *testing.T) {
	_, _ = withManagedTestEnvironment(t)
	managedEUID = func() int { return 1000 }
	for _, call := range []func() error{
		func() error { return setupCommand([]string{"--vpn", managedVPNPath, "--dry-run"}) },
		func() error { return setupRollbackCommand(nil) },
		func() error { return tunnelCommand([]string{"up"}) },
		func() error { return managedBackupCommand([]string{"verify", "/tmp/missing"}) },
		func() error {
			return changeManagedIntent("test", managedMutationOptions{Yes: true}, func(*intent.Intent) error {
				return nil
			})
		},
	} {
		if err := call(); err == nil {
			t.Fatal("non-root managed mutation accepted")
		}
	}
	managedEUID = func() int { return 0 }
	if err := os.Chmod(managedIntentPath, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadManagedIntent(); err == nil {
		t.Fatal("writable managed intent accepted")
	}
}

func managedChangeFixture(t *testing.T) (
	[]byte, []byte, []byte, []byte, managedChangeRecord,
) {
	t.Helper()
	_, _ = withManagedTestEnvironment(t)
	oldIntent, err := readProtectedFile(managedIntentPath, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	oldConfig, err := readProtectedFile(managedConfigPath, 4<<20)
	if err != nil {
		t.Fatal(err)
	}
	value, err := intent.Decode(oldIntent)
	if err != nil {
		t.Fatal(err)
	}
	if err := value.AddExposure("tcp", 443); err != nil {
		t.Fatal(err)
	}
	newIntent, err := value.Render()
	if err != nil {
		t.Fatal(err)
	}
	generated, err := value.Config()
	if err != nil {
		t.Fatal(err)
	}
	newConfig, err := intent.RenderConfig(generated)
	if err != nil {
		t.Fatal(err)
	}
	record, err := prepareManagedChange(
		"add public tcp", oldIntent, oldConfig, newIntent, newConfig,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := managedsetup.WriteAtomicFile(managedIntentPath, newIntent, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := managedsetup.WriteAtomicFile(managedConfigPath, newConfig, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := updateManagedChange(&record, "files_published", 0); err != nil {
		t.Fatal(err)
	}
	return oldIntent, oldConfig, newIntent, newConfig, record
}

func TestManagedChangeRecoversPublishedFilesBeforeApply(t *testing.T) {
	oldIntent, oldConfig, _, _, _ := managedChangeFixture(t)
	if err := managedRecoverCommand(nil); err != nil {
		t.Fatal(err)
	}
	gotIntent, _ := os.ReadFile(managedIntentPath)
	gotConfig, _ := os.ReadFile(managedConfigPath)
	if !reflect.DeepEqual(gotIntent, oldIntent) || !reflect.DeepEqual(gotConfig, oldConfig) {
		t.Fatal("pre-apply crash recovery did not restore exact files")
	}
	if _, err := os.Lstat(managedChangeJournal); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("managed recovery journal remained: %v", err)
	}
}

func TestManagedChangeRecoversAppliedGeneration(t *testing.T) {
	oldIntent, oldConfig, _, _, record := managedChangeFixture(t)
	if err := updateManagedChange(&record, "applied", 42); err != nil {
		t.Fatal(err)
	}
	var requests []api.Request
	managedAPICall = func(_ context.Context, _ string, request api.Request) (api.Response, error) {
		requests = append(requests, request)
		switch request.Op {
		case "generation":
			return api.Response{OK: true, Data: state.Generation{ID: 42, Status: "applied"}}, nil
		case "rollback":
			return api.Response{OK: true}, nil
		default:
			return api.Response{}, errors.New("unexpected")
		}
	}
	if err := managedRecoverCommand(nil); err != nil {
		t.Fatal(err)
	}
	gotIntent, _ := os.ReadFile(managedIntentPath)
	gotConfig, _ := os.ReadFile(managedConfigPath)
	if !reflect.DeepEqual(gotIntent, oldIntent) || !reflect.DeepEqual(gotConfig, oldConfig) {
		t.Fatal("applied-generation crash recovery did not restore exact files")
	}
	if len(requests) != 2 || requests[0].Op != "generation" ||
		requests[1].Op != "rollback" || requests[1].Generation != 42 {
		t.Fatalf("unexpected recovery requests: %#v", requests)
	}
}

func TestManagedChangeKeepsFilesAfterUncertainCommittedResponse(t *testing.T) {
	_, _, newIntent, newConfig, record := managedChangeFixture(t)
	if err := updateManagedChange(&record, "applied", 43); err != nil {
		t.Fatal(err)
	}
	managedAPICall = func(_ context.Context, _ string, request api.Request) (api.Response, error) {
		if request.Op != "generation" || request.Generation != 43 {
			return api.Response{}, errors.New("unexpected")
		}
		return api.Response{OK: true, Data: state.Generation{ID: 43, Status: "committed"}}, nil
	}
	if err := managedRecoverCommand(nil); err != nil {
		t.Fatal(err)
	}
	gotIntent, _ := os.ReadFile(managedIntentPath)
	gotConfig, _ := os.ReadFile(managedConfigPath)
	if !reflect.DeepEqual(gotIntent, newIntent) || !reflect.DeepEqual(gotConfig, newConfig) {
		t.Fatal("committed-generation recovery reverted the new configuration")
	}
	if _, err := os.Lstat(managedChangeJournal); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("committed recovery journal remained: %v", err)
	}
}

func TestManagedChangeExpiredOnlyWaitsForDeadline(t *testing.T) {
	_, _, _, _, record := managedChangeFixture(t)
	managedChangeNow = func() time.Time { return record.Deadline.Add(-time.Second) }
	if err := managedRecoverCommand([]string{"--expired"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(managedChangeJournal); err != nil {
		t.Fatalf("unexpired journal was removed: %v", err)
	}
	managedChangeNow = func() time.Time { return record.Deadline.Add(time.Second) }
	if err := managedRecoverCommand([]string{"--expired"}); err != nil {
		t.Fatal(err)
	}
}

func TestManagedOperatorSummariesAndInternalUsage(t *testing.T) {
	_, _ = withManagedTestEnvironment(t)
	summary := managedsetup.Summary{
		Uplink: "eth0", VPNInterface: "nftfw0",
		LANNetworks: []string{"192.168.1.0/24"}, ManagementTCP: []int{22},
		IPv6Mode: "disabled", DockerMode: "disabled", SourceModeWarning: true,
	}
	printSetupSummary(summary)
	printProtectedSummary(summary, true)
	summary.DockerMode = "enabled"
	summary.DockerNetworks = []string{"bridge", "media"}
	summary.DockerRestart = true
	output := captureManagedOutput(t, func() {
		printSetupSummary(summary)
		printProtectedSummary(summary, false)
	})
	for _, expected := range []string{
		"Docker networks: bridge, media",
		"Docker IPv4 forwarding: NFTFW OWNED",
		"Docker restart required: YES",
		"Docker: PROTECTED (2 networks, IPv4 forwarding NFTFW-owned)",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("Docker operator summary omitted %q:\n%s", expected, output)
		}
	}
	summary.PublicTCP = []int{443}
	summary.PublicUDP = []int{53}
	printProtectedSummary(summary, false)
	if confirmed, err := confirmSetup(); err == nil || confirmed {
		t.Fatalf("non-interactive setup confirmation succeeded: %t %v", confirmed, err)
	}
	if confirmed, err := confirmManagedChange(); err == nil || confirmed {
		t.Fatalf("non-interactive managed confirmation succeeded: %t %v", confirmed, err)
	}
	if err := managedRecoverCommand([]string{"bad"}); err == nil {
		t.Fatal("invalid managed recovery arguments accepted")
	}
	managedEUID = func() int { return 1000 }
	if err := managedRecoverCommand(nil); err == nil {
		t.Fatal("non-root managed recovery accepted")
	}
}

func captureManagedOutput(t *testing.T, operation func()) string {
	t.Helper()
	original := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = writer
	defer func() { os.Stdout = original }()
	operation()
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestManagedChangeStateValidation(t *testing.T) {
	for _, state := range [][2]string{
		{"running", "prepared"},
		{"running", "files_published"},
		{"running", "applied"},
		{"complete", "complete"},
		{"rolled_back", "rolled_back"},
	} {
		if !validManagedChangeState(state[0], state[1]) {
			t.Fatalf("valid managed journal state rejected: %v", state)
		}
	}
	for _, state := range [][2]string{
		{"running", "complete"},
		{"complete", "applied"},
		{"unknown", "prepared"},
	} {
		if validManagedChangeState(state[0], state[1]) {
			t.Fatalf("invalid managed journal state accepted: %v", state)
		}
	}
}
