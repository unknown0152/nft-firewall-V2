package operatorbackup

import (
	"context"
	"encoding/base64"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/unknown0152/nft-firewall-v2/internal/config"
	"github.com/unknown0152/nft-firewall-v2/internal/containers"
	"github.com/unknown0152/nft-firewall-v2/internal/intent"
	"github.com/unknown0152/nft-firewall-v2/internal/provenance"
	"github.com/unknown0152/nft-firewall-v2/internal/state"
	"github.com/unknown0152/nft-firewall-v2/internal/wgconfig"
)

func backupKey(fill byte) string {
	value := make([]byte, 32)
	for index := range value {
		value[index] = fill
	}
	return base64.StdEncoding.EncodeToString(value)
}

func backupFixture(t testing.TB) (Creator, string) {
	t.Helper()
	root := t.TempDir()
	stateRoot := filepath.Join(root, "var/lib/nftfw")
	paths := Paths{
		Config:       filepath.Join(root, "etc/nftfw/nftfw.toml"),
		Intent:       filepath.Join(root, "etc/nftfw/intent.toml"),
		VPN:          filepath.Join(root, "etc/wireguard/nftfw0.conf"),
		Sysctl:       filepath.Join(root, "etc/sysctl.d/90-nftfw-managed.conf"),
		StateDB:      filepath.Join(stateRoot, "generation-state/state.db"),
		Ledger:       filepath.Join(stateRoot, "provenance-ledger.db"),
		Generations:  filepath.Join(stateRoot, "generations"),
		Enforcement:  filepath.Join(stateRoot, "enforcement-enabled"),
		DockerDaemon: filepath.Join(root, "etc/docker/daemon.json"),
		DockerDropIn: filepath.Join(
			root, "etc/systemd/system/nftfwd.service.d/docker-access.conf",
		),
	}
	value := intent.Intent{
		Schema: intent.Schema, Managed: true, Uplink: "eth0",
		VPNInterface: intent.VPNInterface,
		LANNetworks:  []string{"192.168.1.0/24"}, ManagementTCP: []int{22},
		VPNAddresses: []string{"10.8.0.2/32"}, EndpointHost: "vpn.example.test",
		EndpointPort: 51820, BootstrapIPv4: []string{"198.51.100.8/32"},
		DNS: []string{"1.1.1.1"}, MTU: 1420, ResolverMode: "resolvconf",
		DisableIPv6: true,
	}
	intentData, err := value.Render()
	if err != nil {
		t.Fatal(err)
	}
	generated, err := value.Config()
	if err != nil {
		t.Fatal(err)
	}
	generated.State.Directory = stateRoot
	generated.State.Database = paths.StateDB
	generated.State.ProvenanceLedger = paths.Ledger
	configData, err := intent.RenderConfig(generated)
	if err != nil {
		t.Fatal(err)
	}
	profile, _, err := wgconfig.Parse([]byte(`[Interface]
PrivateKey = ` + backupKey(1) + `
Address = 10.8.0.2/32
DNS = 1.1.1.1
[Peer]
PublicKey = ` + backupKey(2) + `
AllowedIPs = 0.0.0.0/0
Endpoint = vpn.example.test:51820
`))
	if err != nil {
		t.Fatal(err)
	}
	vpnData, err := profile.NormalizedWGQuick(intent.VPNInterface)
	if err != nil {
		t.Fatal(err)
	}
	for path, data := range map[string][]byte{
		paths.Config: configData, paths.Intent: intentData, paths.VPN: vpnData,
		paths.Sysctl: []byte("net.ipv6.conf.default.disable_ipv6 = 1\n"),
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	store, err := state.Open(context.Background(), paths.StateDB)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	ledger, err := provenance.Open(context.Background(), paths.Ledger)
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Reserve(context.Background(), []provenance.Assignment{
		{Name: "eth0", ID: 1}, {Name: "nftfw0", ID: 2},
	}); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(paths.Generations, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(paths.Generations, "generation-1.nft"),
		[]byte("table inet nftfw_filter {}\n"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.Enforcement, []byte(strings.Repeat("a", 64)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	lockDir := filepath.Join(root, "run/nftfw")
	if err := os.MkdirAll(lockDir, 0o700); err != nil {
		t.Fatal(err)
	}
	return Creator{
		Paths: paths, LockDir: lockDir,
		Now: func() time.Time {
			return time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
		},
	}, filepath.Join(root, "backups", "managed")
}

func enableDockerBackupFixture(t *testing.T, creator Creator) {
	t.Helper()
	value, err := intent.Load(creator.Paths.Intent)
	if err != nil {
		t.Fatal(err)
	}
	value.DockerEnabled = true
	value.DockerNetworks = []config.DockerNetwork{{
		Name: "media", Driver: "bridge", BridgeInterface: "br-media",
		DynamicBridge: true, Subnets: []string{"172.20.0.0/16"},
		Gateways: []string{"172.20.0.1"},
	}}
	intentData, err := value.Render()
	if err != nil {
		t.Fatal(err)
	}
	generated, err := value.Config()
	if err != nil {
		t.Fatal(err)
	}
	generated.State.Directory = filepath.Dir(filepath.Dir(creator.Paths.StateDB))
	generated.State.Database = creator.Paths.StateDB
	generated.State.ProvenanceLedger = creator.Paths.Ledger
	configData, err := intent.RenderConfig(generated)
	if err != nil {
		t.Fatal(err)
	}
	for path, data := range map[string][]byte{
		creator.Paths.Intent: intentData,
		creator.Paths.Config: configData,
		creator.Paths.DockerDaemon: []byte(
			`{"iptables":false,"ip6tables":false,"ip-forward":false,"ip-masq":false,"userland-proxy":false}` + "\n",
		),
		creator.Paths.DockerDropIn: []byte(containers.ManagedSocketDropIn),
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCreateAndVerifyManagedBackup(t *testing.T) {
	creator, destination := backupFixture(t)
	manifest, err := creator.Create(context.Background(), destination)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Schema != Schema || !manifest.Managed || len(manifest.Files) < 7 {
		t.Fatalf("unexpected manifest: %#v", manifest)
	}
	verified, err := Verify(context.Background(), destination)
	if err != nil {
		t.Fatal(err)
	}
	if len(verified.Files) != len(manifest.Files) {
		t.Fatalf("verified file count differs: %d != %d", len(verified.Files), len(manifest.Files))
	}
	if _, err := creator.Create(context.Background(), destination); err == nil {
		t.Fatal("backup overwrote an existing destination")
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	creator, destination := backupFixture(t)
	if _, err := creator.Create(context.Background(), destination); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(destination, "intent.toml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(context.Background(), destination); err == nil ||
		err.Error() != "BACKUP_CONTENT_MISMATCH" {
		t.Fatalf("tampered backup was accepted: %v", err)
	}
}

func TestVerifyRejectsInvalidDockerOwnershipFiles(t *testing.T) {
	tests := []struct {
		name string
		path func(string) string
		data string
		code string
	}{
		{
			name: "daemon",
			path: func(root string) string { return filepath.Join(root, "docker", "daemon.json") },
			data: `{"iptables":true}`,
			code: "BACKUP_DOCKER_CONFIG_INVALID",
		},
		{
			name: "drop-in",
			path: func(root string) string {
				return filepath.Join(root, "systemd", "nftfwd-docker-access.conf")
			},
			data: "[Service]\nInaccessiblePaths=/run/docker.sock\n",
			code: "BACKUP_DOCKER_DROPIN_INVALID",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			creator, destination := backupFixture(t)
			enableDockerBackupFixture(t, creator)
			manifest, err := creator.Create(context.Background(), destination)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(test.path(destination), []byte(test.data), 0o600); err != nil {
				t.Fatal(err)
			}
			rewriteBackupManifest(t, destination, manifest.CreatedAt)
			if _, err := Verify(context.Background(), destination); err == nil ||
				err.Error() != test.code {
				t.Fatalf("invalid Docker ownership backup accepted: %v", err)
			}
		})
	}
}

func TestCreatorRejectsRelativeDestination(t *testing.T) {
	creator, _ := backupFixture(t)
	if _, err := creator.Create(context.Background(), "relative"); err == nil {
		t.Fatal("relative backup destination accepted")
	}
}

func rewriteBackupManifest(t *testing.T, directory string, createdAt time.Time) {
	t.Helper()
	path := filepath.Join(directory, "manifest.json")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	files, err := inventory(directory, "manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := writeManifest(path, Manifest{
		Schema: Schema, CreatedAt: createdAt, Managed: true, Files: files,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRejectsSemanticallyInvalidProtectedFiles(t *testing.T) {
	tests := []struct {
		name string
		file string
		data string
		code string
	}{
		{"config", "nftfw.toml", "[invalid]\n", "BACKUP_CONFIG_INVALID"},
		{"intent", "intent.toml", "schema = \"invalid\"\n", "BACKUP_INTENT_INVALID"},
		{"vpn", "nftfw0.conf", "[Interface]\nPrivateKey = redacted\n", "BACKUP_VPN_INVALID"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			creator, destination := backupFixture(t)
			manifest, err := creator.Create(context.Background(), destination)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(
				filepath.Join(destination, test.file), []byte(test.data), 0o600,
			); err != nil {
				t.Fatal(err)
			}
			rewriteBackupManifest(t, destination, manifest.CreatedAt)
			if _, err := Verify(context.Background(), destination); err == nil ||
				err.Error() != test.code {
				t.Fatalf("unexpected verification result: %v", err)
			}
		})
	}
}

func TestBackupRejectsUnsafeManifestAndGenerationEntries(t *testing.T) {
	creator, destination := backupFixture(t)
	if _, err := creator.Create(context.Background(), destination); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(destination, "manifest.json")
	if err := os.Chmod(manifestPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(context.Background(), destination); err == nil ||
		err.Error() != "BACKUP_MANIFEST_UNSAFE" {
		t.Fatalf("unsafe manifest accepted: %v", err)
	}

	creator, destination = backupFixture(t)
	if err := os.WriteFile(
		filepath.Join(creator.Paths.Generations, "unexpected.txt"), []byte("bad"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := creator.Create(context.Background(), destination); err == nil ||
		err.Error() != "BACKUP_GENERATIONS_UNSAFE" {
		t.Fatalf("unsafe generation entry accepted: %v", err)
	}
}

func TestBackupOptionalAndHelperBoundaries(t *testing.T) {
	creator, destination := backupFixture(t)
	if err := os.Remove(creator.Paths.Sysctl); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(creator.Paths.Enforcement); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(creator.Paths.Generations); err != nil {
		t.Fatal(err)
	}
	if _, err := creator.Create(context.Background(), destination); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(context.Background(), destination); err != nil {
		t.Fatal(err)
	}
	if validateDestination("/") == nil || validateDestination("relative") == nil ||
		copyOptional(filepath.Join(t.TempDir(), "missing"), filepath.Join(t.TempDir(), "out")) != nil {
		t.Fatal("backup helper boundary changed")
	}
	source := filepath.Join(t.TempDir(), "source")
	if err := os.WriteFile(source, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copyProtected(source, filepath.Join(t.TempDir(), "copy")); err == nil {
		t.Fatal("empty protected source accepted")
	}
	if recordsEqual([]Record{{Path: "a"}}, []Record{{Path: "b"}}) ||
		recordsEqual([]Record{{Path: "a"}}, nil) {
		t.Fatal("record mismatch accepted")
	}
}

func TestFixtureUsesIPv4Only(t *testing.T) {
	if !netip.MustParseAddr("198.51.100.8").Is4() {
		t.Fatal("invalid test fixture")
	}
}
