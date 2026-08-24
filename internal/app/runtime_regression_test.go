package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/unknown0152/nft-firewall-v2/internal/api"
	"github.com/unknown0152/nft-firewall-v2/internal/config"
	"github.com/unknown0152/nft-firewall-v2/internal/nft"
	"github.com/unknown0152/nft-firewall-v2/internal/state"
	"github.com/unknown0152/nft-firewall-v2/internal/threatintel"
)

type captureClaimApplyRunner struct {
	scripts []string
}

func (r *captureClaimApplyRunner) Run(_ context.Context, args ...string) (string, string, error) {
	if len(args) >= 3 && args[0] == "-j" && args[1] == "list" && args[2] == "tables" {
		return `{"nftables":[{"table":{"family":"inet","name":"nftfw_filter"}}]}`, "", nil
	}
	if len(args) > 0 && args[0] == "--file" {
		script, err := os.ReadFile(args[len(args)-1])
		if err != nil {
			return "", "", err
		}
		r.scripts = append(r.scripts, string(script))
	}
	return "", "", nil
}

type cancelFirstClaimApplyRunner struct {
	cancel       context.CancelFunc
	applyCalls   int
	secondCtxErr error
}

func (r *cancelFirstClaimApplyRunner) Run(ctx context.Context, args ...string) (string, string, error) {
	if len(args) >= 3 && args[0] == "-j" && args[1] == "list" && args[2] == "tables" {
		return `{"nftables":[{"table":{"family":"inet","name":"nftfw_filter"}}]}`, "", nil
	}
	if len(args) == 0 || args[0] != "--file" {
		return "", "", nil
	}
	r.applyCalls++
	if r.applyCalls == 1 {
		r.cancel()
		return "", "synthetic canceled publication", errors.New("synthetic canceled publication")
	}
	r.secondCtxErr = ctx.Err()
	if r.secondCtxErr != nil {
		return "", "recovery inherited canceled context", r.secondCtxErr
	}
	return "", "", nil
}

type containerSetRunner struct {
	inspectionErr  error
	replacementErr error
}

type runtimeSetLockRunner struct {
	mutationCalls int
}

func (r *runtimeSetLockRunner) Run(_ context.Context, args ...string) (string, string, error) {
	if len(args) >= 3 && args[0] == "-j" && args[1] == "list" && args[2] == "tables" {
		return `{"nftables":[{"table":{"family":"inet","name":"nftfw_filter"}},{"table":{"family":"ip","name":"nftfw_nat"}}]}`, "", nil
	}
	if len(args) > 0 && args[0] == "--file" {
		r.mutationCalls++
	}
	return "", "", nil
}

func TestPublicRuntimeSetMutationsWaitForGlobalLock(t *testing.T) {
	store := openRuntimeTestStore(t)
	lockDir := secureRuntimeTestDir(t)
	runner := &runtimeSetLockRunner{}
	runtime := &Runtime{Store: store, Backend: nft.New(runner), MutationLockDir: lockDir}
	release, err := state.AcquireMutationLock(context.Background(), lockDir)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	for _, test := range []struct {
		name string
		call func(context.Context) error
	}{
		{name: "endpoints", call: func(ctx context.Context) error { _, err := runtime.RefreshEndpoints(ctx); return err }},
		{name: "claims", call: func(ctx context.Context) error { _, err := runtime.RefreshClaimSets(ctx); return err }},
		{name: "containers", call: func(ctx context.Context) error { _, err := runtime.RefreshContainerSets(ctx); return err }},
		{name: "restore", call: runtime.RestoreRuntimeState},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
			defer cancel()
			if err := test.call(ctx); err == nil || !strings.Contains(err.Error(), "context deadline exceeded") {
				t.Fatalf("public mutation bypassed held global lock: %v", err)
			}
		})
	}
	if runner.mutationCalls != 0 {
		t.Fatalf("blocked public paths reached nft mutation: %d", runner.mutationCalls)
	}
}

func TestRestoreRuntimeStateReusesGenuineHeldLockContext(t *testing.T) {
	store := openRuntimeTestStore(t)
	lockDir := secureRuntimeTestDir(t)
	runner := &runtimeSetLockRunner{}
	runtime := &Runtime{Store: store, Backend: nft.New(runner), MutationLockDir: lockDir}
	release, err := state.AcquireMutationLock(context.Background(), lockDir)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx := state.WithMutationLock(context.WithValue(context.Background(), claimPublicationLockContextKey{}, true))
	if err := runtime.RestoreRuntimeState(ctx); err != nil {
		t.Fatalf("restore self-deadlocked or failed under genuine held lock: %v", err)
	}
	if runner.mutationCalls != 3 {
		t.Fatalf("restore did not publish all mutable set classes: calls=%d", runner.mutationCalls)
	}
}

func (r containerSetRunner) Run(_ context.Context, args ...string) (string, string, error) {
	if len(args) >= 3 && args[0] == "-j" && args[1] == "list" && args[2] == "tables" {
		if r.inspectionErr != nil {
			return "", "synthetic table inspection failure", r.inspectionErr
		}
		return `{"nftables":[{"table":{"family":"inet","name":"nftfw_filter"}},{"table":{"family":"ip","name":"nftfw_nat"}}]}`, "", nil
	}
	if len(args) > 0 && args[0] == "--file" && r.replacementErr != nil {
		return "", "synthetic container replacement failure", r.replacementErr
	}
	return "", "", nil
}

func openRuntimeTestStore(t *testing.T) *state.Store {
	t.Helper()
	store, err := state.Open(context.Background(), filepath.Join(secureRuntimeTestDir(t), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("close state store: %v", err)
		}
	})
	return store
}

func manualClaimRuntime(store *state.Store, runner nft.Runner) *Runtime {
	return &Runtime{
		Config: config.Config{Runtime: config.RuntimeConfig{
			MaxBlockClaims:  100,
			MaxSetMembers:   100,
			TrustedServices: []string{"ssh"},
		}},
		Store: store, Backend: nft.New(runner),
	}
}

func TestManualClaimAddPublicationFailuresAreCompensated(t *testing.T) {
	tests := []struct {
		name    string
		request api.Request
	}{
		{name: "block", request: api.Request{Op: "block-add", Address: "192.0.2.10", Source: "manual", Reason: "test block"}},
		{name: "allow", request: api.Request{Op: "allow-add", Address: "192.0.2.11", Reason: "test access", ExpiresSec: 300}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			store := openRuntimeTestStore(t)
			runner := &failFirstClaimApplyRunner{}
			runtime := manualClaimRuntime(store, runner)

			if _, err := runtime.Control(ctx, test.request); err == nil || !strings.Contains(err.Error(), "publication failed and was reverted") {
				t.Fatalf("publication failure was not reported as compensated: %v", err)
			}
			claims, err := store.Claims(ctx, time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			if len(claims) != 0 {
				t.Fatalf("failed add remained durable: %#v", claims)
			}
			publication, err := store.ClaimPublicationState(ctx)
			if err != nil || publication.DesiredRevision != publication.AppliedRevision {
				t.Fatalf("compensated add remained unpublished: %#v err=%v", publication, err)
			}
			integration, err := store.IntegrationState(ctx, "runtime/claims")
			if err != nil || integration.Status != "healthy" || integration.EntryCount != 0 {
				t.Fatalf("compensated add left degraded publication health: %#v err=%v", integration, err)
			}
			if !strings.Contains(runner.failedScript, strings.TrimSuffix(test.request.Address, "/32")) {
				t.Fatalf("candidate claim did not reach the failed publication: %s", runner.failedScript)
			}
			if strings.Contains(runner.successfulScript, strings.TrimSuffix(test.request.Address, "/32")) {
				t.Fatalf("compensated claim remained in restored live sets: %s", runner.successfulScript)
			}
		})
	}
}

func TestManualClaimRemovePublicationFailuresRestoreExactClaims(t *testing.T) {
	tests := []struct {
		name   string
		kind   string
		claim  state.Claim
		remove func(int64) api.Request
	}{
		{
			name: "block", kind: "block",
			claim:  state.Claim{Address: "192.0.2.20/32", Family: "ipv4", Source: "manual", Reason: "original block", Actor: "original-actor"},
			remove: func(id int64) api.Request { return api.Request{Op: "block-remove", ClaimID: id} },
		},
		{
			name: "allow", kind: "allow",
			claim:  state.Claim{Address: "192.0.2.21/32", Family: "ipv4", Source: "allow", Reason: "original access", Actor: "original-actor"},
			remove: func(id int64) api.Request { return api.Request{Op: "allow-remove", ClaimID: id} },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			store := openRuntimeTestStore(t)
			claim := test.claim
			if test.kind == "allow" {
				expires := time.Now().UTC().Add(10 * time.Minute)
				claim.ExpiresAt = &expires
			}
			id, err := store.AddClaim(ctx, claim)
			if err != nil {
				t.Fatal(err)
			}
			baselineRunner := &captureClaimApplyRunner{}
			runtime := manualClaimRuntime(store, baselineRunner)
			if _, err := runtime.RefreshClaimSets(ctx); err != nil {
				t.Fatal(err)
			}
			beforeClaims, err := store.Claims(ctx, time.Now().UTC())
			if err != nil || len(beforeClaims) != 1 {
				t.Fatalf("baseline claim unavailable: %#v err=%v", beforeClaims, err)
			}
			before := beforeClaims[0]
			failureRunner := &failFirstClaimApplyRunner{}
			runtime.Backend = nft.New(failureRunner)

			if _, err := runtime.Control(ctx, test.remove(id)); err == nil || !strings.Contains(err.Error(), "removal publication failed and was reverted") {
				t.Fatalf("removal publication failure was not compensated: %v", err)
			}
			afterClaims, err := store.Claims(ctx, time.Now().UTC())
			if err != nil || len(afterClaims) != 1 {
				t.Fatalf("removed claim was not restored: %#v err=%v", afterClaims, err)
			}
			assertClaimsEqual(t, afterClaims[0], before)
			publication, err := store.ClaimPublicationState(ctx)
			if err != nil || publication.DesiredRevision != publication.AppliedRevision {
				t.Fatalf("restored claim remained unpublished: %#v err=%v", publication, err)
			}
			integration, err := store.IntegrationState(ctx, "runtime/claims")
			if err != nil || integration.Status != "healthy" || integration.EntryCount != 1 {
				t.Fatalf("restored claim left degraded publication health: %#v err=%v", integration, err)
			}
			if strings.Contains(failureRunner.failedScript, before.Address) {
				t.Fatalf("removed claim remained in failed candidate sets: %s", failureRunner.failedScript)
			}
			if !strings.Contains(failureRunner.successfulScript, before.Address) {
				t.Fatalf("restored claim did not return to live sets: %s", failureRunner.successfulScript)
			}
		})
	}
}

func assertClaimsEqual(t *testing.T, got, want state.Claim) {
	t.Helper()
	if got.ID != want.ID || got.Address != want.Address || got.Family != want.Family || got.Source != want.Source || got.Reason != want.Reason || got.Actor != want.Actor || !got.CreatedAt.Equal(want.CreatedAt) {
		t.Fatalf("restored claim metadata changed:\n got: %#v\nwant: %#v", got, want)
	}
	if got.ExpiresAt == nil != (want.ExpiresAt == nil) || got.ExpiresAt != nil && !got.ExpiresAt.Equal(*want.ExpiresAt) {
		t.Fatalf("restored claim expiry changed: got=%v want=%v", got.ExpiresAt, want.ExpiresAt)
	}
}

func TestManualAddRecoveryUsesDetachedBoundedContext(t *testing.T) {
	store := openRuntimeTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	runner := &cancelFirstClaimApplyRunner{cancel: cancel}
	runtime := manualClaimRuntime(store, runner)

	if _, err := runtime.Control(ctx, api.Request{Op: "block-add", Address: "192.0.2.30", Source: "manual", Reason: "deadline test"}); err == nil {
		t.Fatal("synthetic canceled publication was not reported")
	}
	if runner.applyCalls != 2 || runner.secondCtxErr != nil {
		t.Fatalf("compensation inherited the canceled request: calls=%d recovery_err=%v", runner.applyCalls, runner.secondCtxErr)
	}
	claims, err := store.Claims(context.Background(), time.Now().UTC())
	if err != nil || len(claims) != 0 {
		t.Fatalf("detached compensation did not remove the durable add: %#v err=%v", claims, err)
	}
	publication, err := store.ClaimPublicationState(context.Background())
	if err != nil || publication.DesiredRevision != publication.AppliedRevision {
		t.Fatalf("detached compensation did not republish prior sets: %#v err=%v", publication, err)
	}
}

func TestSameCountClaimSwapIsRepublished(t *testing.T) {
	ctx := context.Background()
	store := openRuntimeTestStore(t)
	firstID, err := store.AddClaim(ctx, state.Claim{Address: "192.0.2.40/32", Family: "ipv4", Source: "manual", Reason: "first", Actor: "test"})
	if err != nil {
		t.Fatal(err)
	}
	runner := &captureClaimApplyRunner{}
	runtime := manualClaimRuntime(store, runner)
	if _, err := runtime.RefreshClaimSets(ctx); err != nil {
		t.Fatal(err)
	}
	if err := store.RemoveClaim(ctx, firstID, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddClaim(ctx, state.Claim{Address: "192.0.2.41/32", Family: "ipv4", Source: "manual", Reason: "second", Actor: "test"}); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.RefreshClaimSets(ctx); err != nil {
		t.Fatal(err)
	}
	if len(runner.scripts) != 2 || !strings.Contains(runner.scripts[0], "192.0.2.40/32") || strings.Contains(runner.scripts[1], "192.0.2.40/32") || !strings.Contains(runner.scripts[1], "192.0.2.41/32") {
		t.Fatalf("same-count replacement was not republished: %#v", runner.scripts)
	}
	publication, err := store.ClaimPublicationState(ctx)
	if err != nil || publication.DesiredRevision != publication.AppliedRevision {
		t.Fatalf("same-count replacement remained dirty: %#v err=%v", publication, err)
	}
}

func TestClaimPublicationLockSerializesRuntimesSharingState(t *testing.T) {
	ctx := context.Background()
	dir := secureRuntimeTestDir(t)
	path := filepath.Join(dir, "state.db")
	firstStore, err := state.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer firstStore.Close()
	secondStore, err := state.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer secondStore.Close()
	first := &Runtime{Store: firstStore}
	second := &Runtime{Store: secondStore}

	releaseFirst, err := first.acquireClaimPublicationLock(ctx)
	if err != nil {
		t.Fatal(err)
	}
	waitCtx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if release, err := second.acquireClaimPublicationLock(waitCtx); release != nil || !errors.Is(err, context.DeadlineExceeded) {
		if release != nil {
			release()
		}
		releaseFirst()
		t.Fatalf("second runtime bypassed the shared-state publication lock: release=%v err=%v", release != nil, err)
	}
	releaseFirst()
	releaseSecond, err := second.acquireClaimPublicationLock(ctx)
	if err != nil {
		t.Fatalf("shared-state lock was not reusable after release: %v", err)
	}
	releaseSecond()
}

func TestSlowIntegrationPreparationDoesNotHoldClaimPublicationLock(t *testing.T) {
	ctx := context.Background()
	store := openRuntimeTestStore(t)
	started := make(chan struct{})
	unblock := make(chan struct{})
	runtime := &Runtime{
		Config: config.Config{
			Runtime:      config.RuntimeConfig{MaxBlockClaims: 100, MaxSetMembers: 100},
			Integrations: config.IntegrationsConfig{ThreatFeed: true},
			ThreatFeeds:  []config.ThreatFeedConfig{{Name: "slow", URL: "https://feed.example.test/list", RefreshSeconds: 1}},
		},
		Store: store, Backend: nft.New(&captureClaimApplyRunner{}),
		threatFeedFetcher: func(context.Context, threatintel.Feed) ([]string, error) {
			close(started)
			<-unblock
			return []string{"8.8.8.8/32"}, nil
		},
	}
	done := make(chan error, 1)
	go func() { done <- runtime.RefreshIntegrations(ctx) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("slow integration preparation did not start")
	}
	lockCtx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	release, err := runtime.acquireClaimPublicationLock(lockCtx)
	cancel()
	if err != nil {
		close(unblock)
		<-done
		t.Fatalf("read-only integration preparation held the publication lock: %v", err)
	}
	release()
	close(unblock)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("integration refresh failed after preparation resumed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("integration refresh did not finish")
	}
}

func TestDockerRefreshFailuresPersistDurableDegradation(t *testing.T) {
	tests := []struct {
		name      string
		fetch     func(context.Context) ([]string, []string, error)
		runner    containerSetRunner
		wantCount int
		wantCause error
	}{
		{
			name: "Docker network inspection",
			fetch: func(context.Context) ([]string, []string, error) {
				return nil, nil, errDockerInspection
			},
			wantCause: errDockerInspection,
		},
		{
			name: "owned table inspection",
			fetch: func(context.Context) ([]string, []string, error) {
				return []string{"172.19.0.0/16"}, nil, nil
			},
			runner: containerSetRunner{inspectionErr: errOwnedInspection}, wantCount: 1, wantCause: errOwnedInspection,
		},
		{
			name: "kernel replacement",
			fetch: func(context.Context) ([]string, []string, error) {
				return []string{"172.19.0.0/16"}, nil, nil
			},
			runner: containerSetRunner{replacementErr: errContainerReplacement}, wantCount: 1, wantCause: errContainerReplacement,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			store := openRuntimeTestStore(t)
			if err := store.SetIntegrationState(ctx, "docker", "healthy", 7, true); err != nil {
				t.Fatal(err)
			}
			runtime := &Runtime{
				Config: config.Config{Integrations: config.IntegrationsConfig{DockerEnabled: true}},
				Store:  store, Backend: nft.New(test.runner), containerNetFetcher: test.fetch,
			}
			if refreshed, err := runtime.RefreshContainerSets(ctx); refreshed || !errors.Is(err, test.wantCause) {
				t.Fatalf("container failure was not propagated: refreshed=%t err=%v", refreshed, err)
			}
			integration, err := store.IntegrationState(ctx, "docker")
			if err != nil || integration.Status != "degraded" || integration.EntryCount != test.wantCount || integration.LastSuccess == nil {
				t.Fatalf("prior healthy Docker state did not become durably degraded: %#v err=%v", integration, err)
			}
		})
	}
}

var (
	errDockerInspection     = errors.New("synthetic Docker inspection failure")
	errOwnedInspection      = errors.New("synthetic owned-table inspection failure")
	errContainerReplacement = errors.New("synthetic container replacement failure")
)

func TestDockerDegradationStateWriteFailureIsPropagated(t *testing.T) {
	ctx := context.Background()
	store := openRuntimeTestStore(t)
	if err := store.SetIntegrationState(ctx, "docker", "healthy", 1, true); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB.ExecContext(ctx, `CREATE TRIGGER fail_docker_degraded BEFORE UPDATE ON integration_state WHEN NEW.name='docker' AND NEW.status='degraded' BEGIN SELECT RAISE(FAIL, 'docker state write blocked'); END`); err != nil {
		t.Fatal(err)
	}
	runtime := &Runtime{
		Config: config.Config{Integrations: config.IntegrationsConfig{DockerEnabled: true}},
		Store:  store, Backend: nft.New(containerSetRunner{}),
		containerNetFetcher: func(context.Context) ([]string, []string, error) {
			return nil, nil, errDockerInspection
		},
	}
	_, err := runtime.RefreshContainerSets(ctx)
	if !errors.Is(err, errDockerInspection) || !strings.Contains(err.Error(), "record Docker integration degradation") || !strings.Contains(err.Error(), "docker state write blocked") {
		t.Fatalf("Docker state persistence error was swallowed: %v", err)
	}
	integration, stateErr := store.IntegrationState(ctx, "docker")
	if stateErr != nil || integration.Status != "healthy" {
		t.Fatalf("failed state write unexpectedly changed the prior row: %#v err=%v", integration, stateErr)
	}
}

func TestDockerFailureAfterRequestCancellationStillPersistsDegraded(t *testing.T) {
	store := openRuntimeTestStore(t)
	if err := store.SetIntegrationState(context.Background(), "docker", "healthy", 1, true); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	runtime := &Runtime{
		Config: config.Config{Integrations: config.IntegrationsConfig{DockerEnabled: true}},
		Store:  store, Backend: nft.New(containerSetRunner{}),
		containerNetFetcher: func(context.Context) ([]string, []string, error) {
			cancel()
			return nil, nil, errDockerInspection
		},
	}
	if _, err := runtime.RefreshContainerSets(ctx); !errors.Is(err, errDockerInspection) {
		t.Fatalf("Docker inspection failure was not propagated: %v", err)
	}
	integration, err := store.IntegrationState(context.Background(), "docker")
	if err != nil || integration.Status != "degraded" || integration.LastSuccess == nil {
		t.Fatalf("canceled request prevented durable Docker degradation: %#v err=%v", integration, err)
	}
}

func TestIntegrationFailureStateWriteErrorsArePropagated(t *testing.T) {
	tests := []struct {
		name      string
		stateName string
		configure func(*Runtime)
	}{
		{
			name: "threat feed", stateName: "threatfeed/test",
			configure: func(runtime *Runtime) {
				runtime.Config.Integrations.ThreatFeed = true
				runtime.Config.ThreatFeeds = []config.ThreatFeedConfig{{Name: "test", URL: "https://feed.example.test/list", RefreshSeconds: 1}}
				runtime.threatFeedFetcher = func(context.Context, threatintel.Feed) ([]string, error) {
					return nil, errors.New("synthetic feed failure")
				}
			},
		},
		{
			name: "GeoIP", stateName: "geo/test",
			configure: func(runtime *Runtime) {
				runtime.Config.Integrations.GeoIP = true
				runtime.Config.GeoSets = []config.GeoSetConfig{{Name: "test", Country: "ZZ", CIDRFile: filepath.Join(runtime.Store.Dir, "missing.cidr"), RefreshSeconds: 1}}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			store := openRuntimeTestStore(t)
			if err := store.SetIntegrationState(ctx, test.stateName, "healthy", 1, true); err != nil {
				t.Fatal(err)
			}
			old := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
			if _, err := store.DB.ExecContext(ctx, `UPDATE integration_state SET updated_at=? WHERE name=?`, old, test.stateName); err != nil {
				t.Fatal(err)
			}
			trigger := `CREATE TRIGGER fail_integration_degraded BEFORE UPDATE ON integration_state WHEN NEW.name='` + test.stateName + `' AND NEW.status='degraded' BEGIN SELECT RAISE(FAIL, 'integration state write blocked'); END`
			if _, err := store.DB.ExecContext(ctx, trigger); err != nil {
				t.Fatal(err)
			}
			runtime := &Runtime{Config: config.Config{Runtime: config.RuntimeConfig{MaxBlockClaims: 100, MaxSetMembers: 100}}, Store: store, Backend: nft.New(&captureClaimApplyRunner{})}
			test.configure(runtime)
			err := runtime.RefreshIntegrations(ctx)
			if err == nil || !strings.Contains(err.Error(), "record degraded integration state") || !strings.Contains(err.Error(), "integration state write blocked") {
				t.Fatalf("integration state persistence failure was swallowed: %v", err)
			}
		})
	}
}

func TestIntegrationCompensationStateWriteErrorIsPropagated(t *testing.T) {
	ctx := context.Background()
	store := openRuntimeTestStore(t)
	const source = "threatfeed/test"
	if _, err := store.ReplaceSourceClaims(ctx, source, "prior", "integration", []string{"8.8.8.8/32"}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetIntegrationState(ctx, source, "healthy", 1, true); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
	if _, err := store.DB.ExecContext(ctx, `UPDATE integration_state SET updated_at=? WHERE name=?`, old, source); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB.ExecContext(ctx, `CREATE TRIGGER fail_compensation_degraded BEFORE UPDATE ON integration_state WHEN NEW.name='threatfeed/test' AND NEW.status='degraded' BEGIN SELECT RAISE(FAIL, 'compensation state write blocked'); END`); err != nil {
		t.Fatal(err)
	}
	runtime := &Runtime{
		Config: config.Config{
			Runtime:      config.RuntimeConfig{MaxBlockClaims: 100, MaxSetMembers: 100},
			Integrations: config.IntegrationsConfig{ThreatFeed: true},
			ThreatFeeds:  []config.ThreatFeedConfig{{Name: "test", URL: "https://feed.example.test/list", RefreshSeconds: 1}},
		},
		Store: store, Backend: nft.New(&failFirstClaimApplyRunner{}),
		threatFeedFetcher: func(context.Context, threatintel.Feed) ([]string, error) {
			return []string{"1.1.1.1/32"}, nil
		},
	}
	err := runtime.RefreshIntegrations(ctx)
	if err == nil || !strings.Contains(err.Error(), "publish refreshed integration claims") || !strings.Contains(err.Error(), "record degraded integration state") || !strings.Contains(err.Error(), "compensation state write blocked") {
		t.Fatalf("integration compensation state failure was swallowed: %v", err)
	}
	addresses, addressErr := runtime.sourceClaimAddresses(ctx, source)
	if addressErr != nil || len(addresses) != 1 || addresses[0] != "8.8.8.8/32" {
		t.Fatalf("integration claims were not compensated despite state error: %v err=%v", addresses, addressErr)
	}
}

func TestClaimPublicationLockRejectsCanceledContextBeforeTouchingState(t *testing.T) {
	store := openRuntimeTestStore(t)
	runtime := &Runtime{Store: store}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	release, err := runtime.acquireClaimPublicationLock(ctx)
	if release != nil {
		release()
		t.Fatal("canceled publication lock returned a release function")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled publication lock returned %v", err)
	}
	if _, statErr := os.Lstat(filepath.Join(store.Dir, ".claim-publication.lock")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("canceled lock acquisition touched shared state: %v", statErr)
	}
}
