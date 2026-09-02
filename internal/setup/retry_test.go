package setup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/unknown0152/nft-firewall-v2/internal/compiler"
	"github.com/unknown0152/nft-firewall-v2/internal/config"
	"github.com/unknown0152/nft-firewall-v2/internal/discovery"
	"github.com/unknown0152/nft-firewall-v2/internal/policy"
	"github.com/unknown0152/nft-firewall-v2/internal/provenance"
	"github.com/unknown0152/nft-firewall-v2/internal/state"
)

type retiredSetupFixture struct {
	system     *System
	paths      Paths
	runner     *systemRunner
	cleanPlan  Plan
	journal    FileJournal
	backup     string
	generation uint64
}

func newRetiredSetupFixture(t testing.TB) retiredSetupFixture {
	t.Helper()
	ctx := context.Background()
	runner := &systemRunner{outputs: map[string][]byte{}}
	system, paths := testSystem(t, runner)
	cleanPlan, err := system.Prepare(ctx, "/provider.conf")
	if err != nil {
		t.Fatal(err)
	}
	private, err := privatePlan(cleanPlan)
	if err != nil {
		t.Fatal(err)
	}
	effective, err := policy.Compile(private.Config)
	if err != nil {
		t.Fatal(err)
	}
	var dockerNets []string
	for _, network := range private.Config.DockerNetworks {
		dockerNets = append(dockerNets, network.Subnets...)
	}
	artifact, err := compiler.Compile(compiler.Input{
		Policy: effective, BootstrapV4: private.Config.WireGuard.BootstrapIPs,
		DockerNets: dockerNets,
	}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(paths.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	ledger, err := provenance.Open(ctx, filepath.Join(paths.StateDir, "provenance-ledger.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Reserve(ctx, artifact.Provenance); err != nil {
		ledger.Close()
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := state.Open(ctx, filepath.Join(paths.StateDir, "generation-state", "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveGenerationWithMetadata(ctx, 1, artifact.Checksum, artifact.Script, nil, nil,
		state.GenerationMetadata{BootID: "test-boot", Provenance: artifact.Provenance}); err != nil {
		store.Close()
		t.Fatal(err)
	}
	if err := store.MarkRolledBack(ctx, 1); err != nil {
		store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	endpointCache := "{\n" +
		"  \"hosts\": {\n" +
		"    \"vpn.example.test\": [\n" +
		"      {\n" +
		"        \"address\": \"198.51.100.8\",\n" +
		"        \"seen_at\": \"2026-08-30T12:00:00Z\"\n" +
		"      }\n" +
		"    ]\n" +
		"  }\n" +
		"}\n"
	if err := os.WriteFile(filepath.Join(paths.StateDir, "wg-endpoints.json"), []byte(endpointCache), 0o600); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(paths.StateDir, "setup", "backups", "20260831T120000.000000000Z")
	if _, err := createBackup(ctx, runner, backup, system.touchedFiles(cleanPlan),
		managedUnits(false), managedSysctls(cleanPlan.Summary.IPv6Interfaces, false)); err != nil {
		t.Fatal(err)
	}
	journal := FileJournal{Path: filepath.Join(paths.StateDir, "setup", "journal.json")}
	terminal := terminalJournalForTest("first-failure", 1)
	terminal.Summary = cleanPlan.Summary
	terminal.BackupDir = backup
	if err := journal.Write(terminal); err != nil {
		t.Fatal(err)
	}
	system.Discover = func(context.Context) (discovery.Snapshot, error) {
		return discovery.Snapshot{
			OSID: "debian", OSVersion: "13", Architecture: "amd64",
			Uplink: "eth0", UplinkGateway: netip.MustParseAddr("192.168.1.1"),
			LANNetworks:        []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
			ManagementTCP:      []int{22},
			DockerClean:        true,
			ExistingNFTFWState: true,
		}, nil
	}
	return retiredSetupFixture{
		system: system, paths: paths, runner: runner, cleanPlan: cleanPlan,
		journal: journal, backup: backup, generation: 1,
	}
}

func BenchmarkRetiredFirstSetupClassification(b *testing.B) {
	fixture := newRetiredSetupFixture(b)
	snapshot, err := fixture.system.Discover(context.Background())
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		fixture.runner.commands = fixture.runner.commands[:0]
		if _, err := inspectRetiredFirstSetup(
			context.Background(), fixture.runner, fixture.paths, snapshot,
		); err != nil {
			b.Fatal(err)
		}
	}
}

func TestRetiredFirstSetupRetryPreservesMonotonicState(t *testing.T) {
	fixture := newRetiredSetupFixture(t)
	snapshot, _ := fixture.system.Discover(context.Background())
	if _, classificationErr := inspectRetiredFirstSetup(context.Background(), fixture.runner, fixture.paths, snapshot); classificationErr != nil {
		t.Fatalf("fixture classification failed: %v", classificationErr)
	}
	beforeDB, err := digestTestFile(filepath.Join(fixture.paths.StateDir, "generation-state", "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	beforeLedger, err := digestTestFile(filepath.Join(fixture.paths.StateDir, "provenance-ledger.db"))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := fixture.system.Prepare(context.Background(), "/provider.conf")
	if err != nil {
		t.Fatalf("strict retired setup was not retryable: %v", err)
	}
	if !validSHA256(plan.PriorJournalSHA256) {
		t.Fatal("retry plan did not bind the exact terminal journal")
	}
	private, _ := privatePlan(plan)
	var candidate []provenance.Assignment
	for _, configured := range private.Config.Interfaces {
		candidate = append(candidate, provenance.Assignment{
			Name: config.InterfaceProvenanceName(configured), ID: configured.ProvenanceID,
		})
	}
	ledger, err := provenance.OpenReadOnly(context.Background(), filepath.Join(fixture.paths.StateDir, "provenance-ledger.db"))
	if err != nil {
		t.Fatal(err)
	}
	retained, err := ledger.Assignments(context.Background())
	ledger.Close()
	if err != nil || !sameProvenanceIdentity(candidate, retained) {
		t.Fatalf("retry changed stable provenance: %#v %v", retained, err)
	}
	store, err := state.OpenReadOnly(context.Background(), filepath.Join(fixture.paths.StateDir, "generation-state", "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	next, err := store.NextGeneration(context.Background())
	store.Close()
	if err != nil || next != 2 {
		t.Fatalf("generation did not advance monotonically: %d %v", next, err)
	}
	afterDB, _ := digestTestFile(filepath.Join(fixture.paths.StateDir, "generation-state", "state.db"))
	afterLedger, _ := digestTestFile(filepath.Join(fixture.paths.StateDir, "provenance-ledger.db"))
	if beforeDB != afterDB || beforeLedger != afterLedger {
		t.Fatal("read-only retry planning mutated retained state")
	}
}

func TestRetiredFirstSetupRequiresInverseBootTerminalGeneration(t *testing.T) {
	fixture := newRetiredSetupFixture(t)
	snapshot, err := fixture.system.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	beforeDB, err := digestTestFile(filepath.Join(fixture.paths.StateDir, "generation-state", "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	beforeLedger, err := digestTestFile(filepath.Join(fixture.paths.StateDir, "provenance-ledger.db"))
	if err != nil {
		t.Fatal(err)
	}
	terminal, err := fixture.journal.Read()
	if err != nil || terminal.Generation != fixture.generation {
		t.Fatalf("invalid retained terminal fixture: %#v err=%v", terminal, err)
	}
	terminal.Generation = 0
	if err := fixture.journal.Write(terminal); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectRetiredFirstSetup(
		context.Background(), fixture.runner, fixture.paths, snapshot,
	); err == nil || err.Error() != "retired setup current journal is not the latest generation" {
		t.Fatalf("cleared inverse-boot generation was not refused: %v", err)
	}
	terminal.Generation = fixture.generation
	if err := fixture.journal.Write(terminal); err != nil {
		t.Fatal(err)
	}
	classified, err := inspectRetiredFirstSetup(
		context.Background(), fixture.runner, fixture.paths, snapshot,
	)
	if err != nil || classified.LatestGeneration != fixture.generation ||
		!validSHA256(classified.PriorJournalSHA256) {
		t.Fatalf("preserved inverse-boot lineage was not retryable: %#v err=%v", classified, err)
	}
	afterDB, _ := digestTestFile(filepath.Join(fixture.paths.StateDir, "generation-state", "state.db"))
	afterLedger, _ := digestTestFile(filepath.Join(fixture.paths.StateDir, "provenance-ledger.db"))
	if beforeDB != afterDB || beforeLedger != afterLedger {
		t.Fatal("inverse-boot lineage classification mutated retained state")
	}
}

func TestRetiredFirstSetupRepeatedTerminalLineage(t *testing.T) {
	fixture := newRetiredSetupFixture(t)
	plan, err := fixture.system.Prepare(context.Background(), "/provider.conf")
	if err != nil {
		t.Fatal(err)
	}
	second := runningJournalForTest("second-failure")
	second.Summary = plan.Summary
	if err := fixture.journal.Begin(second, plan.PriorJournalSHA256); err != nil {
		t.Fatal(err)
	}
	secondBackup := filepath.Join(fixture.paths.StateDir, "setup", "backups", "20260831T120100.000000000Z")
	if _, err := createBackup(context.Background(), fixture.runner, secondBackup,
		fixture.system.touchedFiles(plan), managedUnits(false),
		managedSysctls(plan.Summary.IPv6Interfaces, false)); err != nil {
		t.Fatal(err)
	}
	addRetiredGeneration(t, fixture, 2)
	second.Phase, second.Status = PhaseFailed, "rolled_back"
	second.UpdatedAt = second.StartedAt.Add(30 * time.Second)
	second.ErrorCode = "SETUP_SECOND_FAILURE"
	second.Generation = 2
	second.BackupDir = secondBackup
	if err := fixture.journal.Write(second); err != nil {
		t.Fatal(err)
	}
	retry, err := fixture.system.Prepare(context.Background(), "/provider.conf")
	if err != nil || !validSHA256(retry.PriorJournalSHA256) {
		t.Fatalf("second terminal retry was not classified: %#v %v", retry, err)
	}
	entries, err := os.ReadDir(filepath.Join(fixture.paths.StateDir, "setup", "history"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("durable terminal lineage missing: %d %v", len(entries), err)
	}
	store, err := state.OpenReadOnly(context.Background(), filepath.Join(fixture.paths.StateDir, "generation-state", "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	next, err := store.NextGeneration(context.Background())
	store.Close()
	if err != nil || next != 3 {
		t.Fatalf("second failed retry did not retain monotonic generation lineage: %d %v", next, err)
	}
}

func TestRetiredFirstSetupPredicatesFailClosed(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(t *testing.T, fixture retiredSetupFixture)
	}{
		{"enforcement-pointer", func(t *testing.T, fixture retiredSetupFixture) {
			if err := os.WriteFile(filepath.Join(fixture.paths.StateDir, "enforcement-enabled"), []byte("active\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"backup-target", func(t *testing.T, fixture retiredSetupFixture) {
			if err := os.MkdirAll(filepath.Dir(fixture.paths.Intent), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(fixture.paths.Intent, []byte("unexpected\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"journal-running", func(t *testing.T, fixture retiredSetupFixture) {
			journal := runningJournalForTest("not-terminal")
			journal.Summary = fixture.cleanPlan.Summary
			if err := fixture.journal.Write(journal); err != nil {
				t.Fatal(err)
			}
		}},
		{"journal-generation-without-backup", func(t *testing.T, fixture retiredSetupFixture) {
			journal := terminalJournalForTest("missing-backup", 1)
			journal.Summary = fixture.cleanPlan.Summary
			if err := fixture.journal.Write(journal); err != nil {
				t.Fatal(err)
			}
		}},
		{"journal-summary-lineage", func(t *testing.T, fixture retiredSetupFixture) {
			_, _, digest, err := readJournalFile(fixture.journal.Path)
			if err != nil {
				t.Fatal(err)
			}
			journal := runningJournalForTest("changed-summary")
			journal.Summary = fixture.cleanPlan.Summary
			journal.Summary.Uplink = "other0"
			if err := fixture.journal.Begin(journal, digest); err != nil {
				t.Fatal(err)
			}
			journal.Phase, journal.Status = PhaseFailed, "rolled_back"
			journal.ErrorCode = "SETUP_CHANGED_SUMMARY"
			if err := fixture.journal.Write(journal); err != nil {
				t.Fatal(err)
			}
		}},
		{"journal-history-extra", func(t *testing.T, fixture retiredSetupFixture) {
			history := filepath.Join(fixture.paths.StateDir, "setup", "history")
			if err := os.Mkdir(history, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(history, "unexpected"), []byte("bad\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"backup-path-outside", func(t *testing.T, fixture retiredSetupFixture) {
			journal, err := fixture.journal.Read()
			if err != nil {
				t.Fatal(err)
			}
			journal.BackupDir = filepath.Join(fixture.paths.StateDir, "outside")
			if err := fixture.journal.Write(journal); err != nil {
				t.Fatal(err)
			}
		}},
		{"generation-pending", func(t *testing.T, fixture retiredSetupFixture) {
			store, err := state.Open(context.Background(), filepath.Join(fixture.paths.StateDir, "generation-state", "state.db"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.DB.Exec("UPDATE generations SET status='pending' WHERE id=1"); err != nil {
				store.Close()
				t.Fatal(err)
			}
			store.Close()
		}},
		{"ledger-missing", func(t *testing.T, fixture retiredSetupFixture) {
			if err := os.Rename(filepath.Join(fixture.paths.StateDir, "provenance-ledger.db"), filepath.Join(fixture.paths.StateDir, "ledger.saved")); err != nil {
				t.Fatal(err)
			}
		}},
		{"ledger-tombstone", func(t *testing.T, fixture retiredSetupFixture) {
			path := filepath.Join(fixture.paths.StateDir, "provenance-ledger.db")
			ledger, err := provenance.Open(context.Background(), path)
			if err != nil {
				t.Fatal(err)
			}
			existing, err := ledger.Assignments(context.Background())
			if err != nil {
				ledger.Close()
				t.Fatal(err)
			}
			withOld := append(append([]provenance.Assignment(nil), existing...), provenance.Assignment{Name: "old0", ID: 3})
			if err := ledger.Reserve(context.Background(), withOld); err != nil {
				ledger.Close()
				t.Fatal(err)
			}
			if err := ledger.Reserve(context.Background(), existing); err != nil {
				ledger.Close()
				t.Fatal(err)
			}
			ledger.Close()
		}},
		{"endpoint-cache", func(t *testing.T, fixture retiredSetupFixture) {
			if err := os.WriteFile(filepath.Join(fixture.paths.StateDir, "wg-endpoints.json"), []byte(`{"hosts":{},"unknown":true}`), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"generation-predecessor", func(t *testing.T, fixture retiredSetupFixture) {
			store, err := state.Open(context.Background(), filepath.Join(fixture.paths.StateDir, "generation-state", "state.db"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.DB.Exec("UPDATE generations SET previous_id=1 WHERE id=1"); err != nil {
				store.Close()
				t.Fatal(err)
			}
			store.Close()
		}},
		{"immutable-snapshot", func(t *testing.T, fixture retiredSetupFixture) {
			path := filepath.Join(fixture.paths.StateDir, "generations", "00000000000000000001.snapshot.json")
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"owned-table", func(_ *testing.T, fixture retiredSetupFixture) {
			prior := fixture.system.Discover
			fixture.system.Discover = func(ctx context.Context) (discovery.Snapshot, error) {
				snapshot, err := prior(ctx)
				snapshot.OwnedNFTables = true
				return snapshot, err
			}
		}},
		{"database-unsafe", func(t *testing.T, fixture retiredSetupFixture) {
			path := filepath.Join(fixture.paths.StateDir, "generation-state", "state.db")
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"ledger-unsafe", func(t *testing.T, fixture retiredSetupFixture) {
			if err := os.Chmod(filepath.Join(fixture.paths.StateDir, "provenance-ledger.db"), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"database-absent-artifacts-retained", func(t *testing.T, fixture retiredSetupFixture) {
			for _, path := range []string{
				filepath.Join(fixture.paths.StateDir, "generation-state", "state.db"),
				filepath.Join(fixture.paths.StateDir, "provenance-ledger.db"),
			} {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			}
			journal := terminalJournalForTest("no-generation", 0)
			journal.Summary = fixture.cleanPlan.Summary
			journal.BackupDir = ""
			if err := fixture.journal.Write(journal); err != nil {
				t.Fatal(err)
			}
		}},
		{"database-without-backup", func(t *testing.T, fixture retiredSetupFixture) {
			journal := terminalJournalForTest("no-backup", 0)
			journal.Summary = fixture.cleanPlan.Summary
			journal.BackupDir = ""
			if err := fixture.journal.Write(journal); err != nil {
				t.Fatal(err)
			}
		}},
		{"database-corrupt", func(t *testing.T, fixture retiredSetupFixture) {
			path := filepath.Join(fixture.paths.StateDir, "generation-state", "state.db")
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("not a database"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"generation-history-empty", func(t *testing.T, fixture retiredSetupFixture) {
			store, err := state.Open(context.Background(), filepath.Join(fixture.paths.StateDir, "generation-state", "state.db"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.DB.Exec("DELETE FROM generations"); err != nil {
				store.Close()
				t.Fatal(err)
			}
			store.Close()
		}},
		{"duplicate-journal-generation", func(t *testing.T, fixture retiredSetupFixture) {
			journal := terminalJournalForTest("duplicate-generation", 1)
			journal.Summary = fixture.cleanPlan.Summary
			journal.BackupDir = fixture.backup
			temporary := FileJournal{Path: filepath.Join(fixture.paths.StateDir, "setup", "duplicate.json")}
			if err := temporary.Write(journal); err != nil {
				t.Fatal(err)
			}
			_, raw, digest, err := readJournalFile(temporary.Path)
			if err != nil {
				t.Fatal(err)
			}
			if err := archiveTerminalJournal(filepath.Join(fixture.paths.StateDir, "setup"), journal, raw, digest); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(temporary.Path); err != nil {
				t.Fatal(err)
			}
		}},
		{"current-journal-not-latest", func(t *testing.T, fixture retiredSetupFixture) {
			addRetiredGeneration(t, fixture, 2)
			backup := filepath.Join(fixture.paths.StateDir, "setup", "backups", "20260831T120200.000000000Z")
			if _, err := createBackup(context.Background(), fixture.runner, backup,
				fixture.system.touchedFiles(fixture.cleanPlan), managedUnits(false),
				managedSysctls(fixture.cleanPlan.Summary.IPv6Interfaces, false)); err != nil {
				t.Fatal(err)
			}
			newer := terminalJournalForTest("newer-archived", 2)
			newer.Summary = fixture.cleanPlan.Summary
			newer.BackupDir = backup
			temporary := FileJournal{Path: filepath.Join(fixture.paths.StateDir, "setup", "newer.json")}
			if err := temporary.Write(newer); err != nil {
				t.Fatal(err)
			}
			_, raw, digest, err := readJournalFile(temporary.Path)
			if err != nil {
				t.Fatal(err)
			}
			if err := archiveTerminalJournal(filepath.Join(fixture.paths.StateDir, "setup"), newer, raw, digest); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(temporary.Path); err != nil {
				t.Fatal(err)
			}
		}},
		{"duplicate-backup-lineage", func(t *testing.T, fixture retiredSetupFixture) {
			current, raw, digest, err := readJournalFile(fixture.journal.Path)
			if err != nil {
				t.Fatal(err)
			}
			if err := archiveTerminalJournal(filepath.Join(fixture.paths.StateDir, "setup"), current, raw, digest); err != nil {
				t.Fatal(err)
			}
			addRetiredGeneration(t, fixture, 2)
			second := terminalJournalForTest("duplicate-backup", 2)
			second.Summary = fixture.cleanPlan.Summary
			second.BackupDir = fixture.backup
			if err := fixture.journal.Write(second); err != nil {
				t.Fatal(err)
			}
		}},
		{"generation-id-gap", func(t *testing.T, fixture retiredSetupFixture) {
			addRetiredGeneration(t, fixture, 2)
			store, err := state.Open(context.Background(), filepath.Join(fixture.paths.StateDir, "generation-state", "state.db"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.DB.Exec("DELETE FROM generations WHERE id=1"); err != nil {
				store.Close()
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			for _, suffix := range []string{".nft", ".snapshot.json"} {
				if err := os.Remove(filepath.Join(fixture.paths.StateDir, "generations", "00000000000000000001"+suffix)); err != nil {
					t.Fatal(err)
				}
			}
			current := terminalJournalForTest("gap-current", 2)
			current.Summary = fixture.cleanPlan.Summary
			current.BackupDir = fixture.backup
			if err := fixture.journal.Write(current); err != nil {
				t.Fatal(err)
			}
		}},
		{"generation-inventory-extra", func(t *testing.T, fixture retiredSetupFixture) {
			path := filepath.Join(fixture.paths.StateDir, "generations", "unexpected")
			if err := os.WriteFile(path, []byte("unexpected\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"generation-without-journal", func(t *testing.T, fixture retiredSetupFixture) {
			addRetiredGeneration(t, fixture, 2)
		}},
		{"snapshot-path", func(t *testing.T, fixture retiredSetupFixture) {
			store, err := state.Open(context.Background(), filepath.Join(fixture.paths.StateDir, "generation-state", "state.db"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.DB.Exec("UPDATE generations SET snapshot_path=? WHERE id=1", "/tmp/wrong.snapshot"); err != nil {
				store.Close()
				t.Fatal(err)
			}
			store.Close()
		}},
		{"journal-unknown-generation", func(t *testing.T, fixture retiredSetupFixture) {
			current, raw, digest, err := readJournalFile(fixture.journal.Path)
			if err != nil {
				t.Fatal(err)
			}
			if err := archiveTerminalJournal(filepath.Join(fixture.paths.StateDir, "setup"), current, raw, digest); err != nil {
				t.Fatal(err)
			}
			unknown := terminalJournalForTest("unknown-generation", 2)
			unknown.Summary = fixture.cleanPlan.Summary
			unknown.BackupDir = fixture.backup
			if err := fixture.journal.Write(unknown); err != nil {
				t.Fatal(err)
			}
		}},
		{"ledger-corrupt", func(t *testing.T, fixture retiredSetupFixture) {
			path := filepath.Join(fixture.paths.StateDir, "provenance-ledger.db")
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("not a database"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"endpoint-cache-unsafe", func(t *testing.T, fixture retiredSetupFixture) {
			if err := os.Chmod(filepath.Join(fixture.paths.StateDir, "wg-endpoints.json"), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"identity-change", func(_ *testing.T, fixture retiredSetupFixture) {
			prior := fixture.system.Discover
			fixture.system.Discover = func(ctx context.Context) (discovery.Snapshot, error) {
				snapshot, err := prior(ctx)
				snapshot.Uplink = "eth1"
				snapshot.NonLoopbackInterfaces = []string{"eth1"}
				return snapshot, err
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newRetiredSetupFixture(t)
			test.mutate(t, fixture)
			_, err := fixture.system.Prepare(context.Background(), "/provider.conf")
			if err == nil || err.Error() != "DISCOVERY_EXISTING_NFTFW_REQUIRES_ADOPT" {
				t.Fatalf("ambiguous retired state was not fail-closed: %v", err)
			}
		})
	}
}

func addRetiredGeneration(t testing.TB, fixture retiredSetupFixture, id uint64) {
	t.Helper()
	private, err := privatePlan(fixture.cleanPlan)
	if err != nil {
		t.Fatal(err)
	}
	effective, err := policy.Compile(private.Config)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := compiler.Compile(compiler.Input{
		Policy: effective, BootstrapV4: private.Config.WireGuard.BootstrapIPs,
	}, id)
	if err != nil {
		t.Fatal(err)
	}
	store, err := state.Open(context.Background(), filepath.Join(fixture.paths.StateDir, "generation-state", "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.SaveGenerationWithMetadata(context.Background(), id, artifact.Checksum, artifact.Script,
		nil, nil, state.GenerationMetadata{BootID: "test-boot", Provenance: artifact.Provenance}); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkRolledBack(context.Background(), id); err != nil {
		t.Fatal(err)
	}
}

func digestTestFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

func TestPreMutationTerminalWithoutRetainedGenerationCanRetry(t *testing.T) {
	runner := &systemRunner{outputs: map[string][]byte{}}
	system, paths := testSystem(t, runner)
	clean, err := system.Prepare(context.Background(), "/provider.conf")
	if err != nil {
		t.Fatal(err)
	}
	journal := FileJournal{Path: filepath.Join(paths.StateDir, "setup", "journal.json")}
	terminal := terminalJournalForTest("backup-failed", 0)
	terminal.Summary = clean.Summary
	terminal.BackupDir = ""
	if err := journal.Write(terminal); err != nil {
		t.Fatal(err)
	}
	system.Discover = func(context.Context) (discovery.Snapshot, error) {
		return discovery.Snapshot{
			OSID: "debian", OSVersion: "13", Architecture: "amd64", Uplink: "eth0",
			UplinkGateway: netip.MustParseAddr("192.168.1.1"),
			LANNetworks:   []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
			ManagementTCP: []int{22}, DockerClean: true, ExistingNFTFWState: true,
		}, nil
	}
	snapshot, _ := system.Discover(context.Background())
	_, classificationErr := inspectRetiredFirstSetup(context.Background(), runner, paths, snapshot)
	if classificationErr != nil {
		t.Fatalf("pre-mutation fixture classification failed: %v", classificationErr)
	}
	plan, err := system.Prepare(context.Background(), "/provider.conf")
	if err != nil || !validSHA256(plan.PriorJournalSHA256) {
		t.Fatalf("nonmutating terminal retry was rejected: %#v %v", plan, err)
	}
}

func TestRetiredRetryHelperPredicateMatrix(t *testing.T) {
	fixture := newRetiredSetupFixture(t)
	if _, err := inspectRetiredFirstSetup(context.Background(), fixture.runner, fixture.paths, discovery.Snapshot{}); err == nil {
		t.Fatal("non-existing setup was classified as retired state")
	}
	loadManifest := func(t *testing.T) backupManifest {
		t.Helper()
		manifest, err := readBackup(fixture.backup)
		if err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		var copy backupManifest
		if err := json.Unmarshal(data, &copy); err != nil {
			t.Fatal(err)
		}
		return copy
	}
	if !backupMatchesRetiredPlan(fixture.paths, fixture.cleanPlan.Summary, loadManifest(t)) {
		t.Fatal("valid retired backup plan did not match")
	}
	for _, test := range []struct {
		name   string
		mutate func(*backupManifest)
	}{
		{"file-count", func(value *backupManifest) { value.Files = value.Files[:len(value.Files)-1] }},
		{"file-path", func(value *backupManifest) { value.Files[0].Path += ".changed" }},
		{"missing-unit", func(value *backupManifest) { delete(value.Units, "nftfw-early.service") }},
		{"active-unit", func(value *backupManifest) {
			state := value.Units["nftfw-early.service"]
			state.Active = true
			value.Units["nftfw-early.service"] = state
		}},
		{"extra-unit", func(value *backupManifest) { value.Units["other.service"] = unitState{} }},
		{"sysctl-count", func(value *backupManifest) {
			delete(value.Sysctls, "net.ipv6.conf.default.disable_ipv6")
		}},
		{"sysctl-key", func(value *backupManifest) {
			delete(value.Sysctls, "net.ipv6.conf.default.disable_ipv6")
			value.Sysctls["net.ipv6.conf.other.disable_ipv6"] = "0"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			manifest := loadManifest(t)
			test.mutate(&manifest)
			if backupMatchesRetiredPlan(fixture.paths, fixture.cleanPlan.Summary, manifest) {
				t.Fatal("ambiguous backup plan matched")
			}
		})
	}
	for _, test := range []struct {
		name string
		make func(t *testing.T) string
	}{
		{"absent", func(t *testing.T) string { return filepath.Join(t.TempDir(), "absent") }},
		{"regular", func(t *testing.T) string {
			path := filepath.Join(t.TempDir(), "regular")
			if err := os.WriteFile(path, []byte("data"), 0o600); err != nil {
				t.Fatal(err)
			}
			return path
		}},
		{"symlink", func(t *testing.T) string {
			root := t.TempDir()
			target := filepath.Join(root, "target")
			if err := os.WriteFile(target, []byte("data"), 0o600); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(root, "link")
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			return link
		}},
		{"unsafe-mode", func(t *testing.T) string {
			path := filepath.Join(t.TempDir(), "mode")
			if err := os.WriteFile(path, []byte("data"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}
			return path
		}},
	} {
		t.Run("path-"+test.name, func(t *testing.T) {
			path := test.make(t)
			exists, err := regularPathExists(path)
			switch test.name {
			case "absent":
				if exists || err != nil {
					t.Fatalf("absent path result=%t %v", exists, err)
				}
			case "regular":
				if !exists || err != nil {
					t.Fatalf("regular path result=%t %v", exists, err)
				}
			default:
				if err == nil {
					t.Fatal("unsafe retained path accepted")
				}
			}
		})
	}
	regular := filepath.Join(t.TempDir(), "digest")
	if err := os.WriteFile(regular, []byte("digest data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if digest, err := digestRetainedFile(regular, 64); err != nil || !validSHA256(digest) {
		t.Fatalf("valid retained digest failed: %s %v", digest, err)
	}
	if _, err := digestRetainedFile(regular, 2); err == nil {
		t.Fatal("oversized retained digest accepted")
	}
	if _, err := digestRetainedFile(filepath.Join(t.TempDir(), "missing"), 64); err == nil {
		t.Fatal("missing retained digest accepted")
	}
	empty := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := digestRetainedFile(empty, 64); err == nil {
		t.Fatal("empty retained digest accepted")
	}
	digestRoot := t.TempDir()
	digestTarget := filepath.Join(digestRoot, "target")
	if err := os.WriteFile(digestTarget, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(digestTarget, filepath.Join(digestRoot, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := digestRetainedFile(filepath.Join(digestRoot, "link"), 64); err == nil {
		t.Fatal("symlink retained digest accepted")
	}
	if retainedGenerationArtifacts(t.TempDir()) {
		t.Fatal("empty retained root reported generation artifacts")
	}
	artifactRoot := t.TempDir()
	if err := os.Mkdir(filepath.Join(artifactRoot, "generations"), 0o700); err != nil {
		t.Fatal(err)
	}
	if !retainedGenerationArtifacts(artifactRoot) || hasGenerationJournal([]Journal{{Generation: 0}}) ||
		!hasGenerationJournal([]Journal{{Generation: 1}}) {
		t.Fatal("retained generation helper classification failed")
	}
}

func TestTerminalJournalLineageDirectoryBoundaries(t *testing.T) {
	current := terminalJournalForTest("current", 0)
	for _, test := range []struct {
		name  string
		build func(t *testing.T, history string)
	}{
		{"unsafe-mode", func(t *testing.T, history string) {
			if err := os.Mkdir(history, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(history, 0o755); err != nil {
				t.Fatal(err)
			}
		}},
		{"directory-entry", func(t *testing.T, history string) {
			if err := os.MkdirAll(filepath.Join(history, "unexpected"), 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{"entry-limit", func(t *testing.T, history string) {
			if err := os.Mkdir(history, 0o700); err != nil {
				t.Fatal(err)
			}
			for index := 0; index <= maxRetiredSetupEntries; index++ {
				path := filepath.Join(history, fmt.Sprintf("entry-%04d", index))
				if err := os.WriteFile(path, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			parent := t.TempDir()
			test.build(t, filepath.Join(parent, "history"))
			if _, err := readTerminalJournalLineage(parent, current, nil, ""); err == nil {
				t.Fatal("unsafe journal history was accepted")
			}
		})
	}
}

func TestRetiredGenerationInventoryDirectoryBoundaries(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		root := t.TempDir()
		directory := filepath.Join(root, "generations")
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{
			"00000000000000000001.nft",
			"00000000000000000001.snapshot.json",
		} {
			if err := os.WriteFile(filepath.Join(directory, name), []byte("fixture\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if err := verifyRetiredGenerationInventory(root, []uint64{1}); err != nil {
			t.Fatalf("valid generation inventory refused: %v", err)
		}
	})

	for _, test := range []struct {
		name  string
		build func(t *testing.T, root string)
	}{
		{"absent", func(_ *testing.T, _ string) {}},
		{"unsafe-mode", func(t *testing.T, root string) {
			directory := filepath.Join(root, "generations")
			if err := os.Mkdir(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(directory, 0o722); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlink", func(t *testing.T, root string) {
			target := filepath.Join(root, "generation-target")
			if err := os.Mkdir(target, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(root, "generations")); err != nil {
				t.Fatal(err)
			}
		}},
		{"non-regular-entry", func(t *testing.T, root string) {
			directory := filepath.Join(root, "generations")
			if err := os.Mkdir(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(directory, "00000000000000000001.nft"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(directory, "00000000000000000001.snapshot.json"), []byte("fixture\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			test.build(t, root)
			if err := verifyRetiredGenerationInventory(root, []uint64{1}); err == nil {
				t.Fatal("unsafe generation inventory was accepted")
			}
		})
	}
}

func TestRetiredGenerationIDsFailClosed(t *testing.T) {
	t.Run("zero-id", func(t *testing.T) {
		fixture := newRetiredSetupFixture(t)
		store, err := state.Open(context.Background(), filepath.Join(fixture.paths.StateDir, "generation-state", "state.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		if _, err := store.DB.Exec("UPDATE generations SET id=0 WHERE id=1"); err != nil {
			t.Fatal(err)
		}
		if _, err := retiredGenerationIDs(context.Background(), store); err == nil {
			t.Fatal("zero generation identity was accepted")
		}
	})

	t.Run("closed-store", func(t *testing.T) {
		fixture := newRetiredSetupFixture(t)
		store, err := state.OpenReadOnly(context.Background(), filepath.Join(fixture.paths.StateDir, "generation-state", "state.db"))
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := retiredGenerationIDs(context.Background(), store); err == nil {
			t.Fatal("closed generation database was accepted")
		}
	})
}

func TestRetiredRetryResumesAfterTerminalArchivePublicationCrash(t *testing.T) {
	fixture := newRetiredSetupFixture(t)
	current, raw, digest, err := readJournalFile(fixture.journal.Path)
	if err != nil {
		t.Fatal(err)
	}
	if err := archiveTerminalJournal(
		filepath.Join(fixture.paths.StateDir, "setup"), current, raw, digest,
	); err != nil {
		t.Fatal(err)
	}
	plan, err := fixture.system.Prepare(context.Background(), "/provider.conf")
	if err != nil || plan.PriorJournalSHA256 != digest {
		t.Fatalf("exact archived-current crash residue was not retryable: %#v %v", plan, err)
	}
	next := runningJournalForTest("retry-after-archive-crash")
	next.Summary = plan.Summary
	if err := fixture.journal.Begin(next, plan.PriorJournalSHA256); err != nil {
		t.Fatalf("idempotent journal begin after archive crash failed: %v", err)
	}
	published, err := fixture.journal.Read()
	if err != nil || published.Transaction != next.Transaction {
		t.Fatalf("new journal was not published after archive crash: %#v %v", published, err)
	}
}

func TestTerminalJournalLineageRejectsChangedCurrentArchive(t *testing.T) {
	currentStore := testFileJournal(t)
	parent := filepath.Dir(currentStore.Path)
	current := terminalJournalForTest("same-transaction", 1)
	if err := currentStore.Write(current); err != nil {
		t.Fatal(err)
	}
	_, currentRaw, currentSHA, err := readJournalFile(currentStore.Path)
	if err != nil {
		t.Fatal(err)
	}
	changed := current
	changed.ErrorCode = "SETUP_DIFFERENT_FAILURE"
	changedStore := FileJournal{Path: filepath.Join(parent, "changed.json")}
	if err := changedStore.Write(changed); err != nil {
		t.Fatal(err)
	}
	_, changedRaw, changedSHA, err := readJournalFile(changedStore.Path)
	if err != nil {
		t.Fatal(err)
	}
	if err := archiveTerminalJournal(parent, changed, changedRaw, changedSHA); err != nil {
		t.Fatal(err)
	}
	if _, err := readTerminalJournalLineage(parent, current, currentRaw, currentSHA); err == nil {
		t.Fatal("changed archive sharing the current transaction identity was accepted")
	}
}
