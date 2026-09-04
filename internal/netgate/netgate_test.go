package netgate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type fakeRunner struct {
	values map[string][]byte
	fail   string
}

func (r fakeRunner) Run(_ context.Context, _ []byte, name string, args ...string) ([]byte, error) {
	command := name + " " + strings.Join(args, " ")
	if r.fail != "" && strings.Contains(command, r.fail) {
		return nil, errors.New("injected")
	}
	if value, ok := r.values[command]; ok {
		return value, nil
	}
	return absentState(args[len(args)-1]), nil
}

func loadedState(probe, unit, active, enabled string) []byte {
	return []byte("Id=" + probe + "\nLoadState=loaded\nActiveState=" + active +
		"\nFragmentPath=/usr/lib/systemd/system/" + unit + "\nUnitFileState=" + enabled + "\n")
}

func absentState(probe string) []byte {
	return []byte("Id=" + probe + "\nLoadState=not-found\nActiveState=inactive\nFragmentPath=\nUnitFileState=\n")
}

func writeMode(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func cleanRunner() fakeRunner {
	property := "systemctl show --property=Id,LoadState,ActiveState,UnitFileState,FragmentPath "
	return fakeRunner{values: map[string][]byte{
		property + "networking.service":       loadedState("networking.service", "networking.service", "active", "enabled"),
		property + "ifup@nftfw-probe.service": loadedState("ifup@nftfw-probe.service", "ifup@.service", "inactive", "static"),
		property + "systemd-networkd.service": loadedState("systemd-networkd.service", "systemd-networkd.service", "inactive", "disabled"),
	}}
}

func TestDiscoverCapturesPrimaryAndDirectTemplate(t *testing.T) {
	units, err := Discover(context.Background(), cleanRunner())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"ifup@.service", "networking.service", "systemd-networkd.service"}
	if !reflect.DeepEqual(units, want) {
		t.Fatalf("units=%v want=%v", units, want)
	}
	data, err := BootMarkerData(units)
	if err != nil || string(data) != "nftfw.setup-network-producers.v1\nifup@.service\nnetworking.service\nsystemd-networkd.service\n" {
		t.Fatalf("marker=%q err=%v", data, err)
	}
}

func TestDiscoverSupportsEveryClosedDebianPrimary(t *testing.T) {
	property := "systemctl show --property=Id,LoadState,ActiveState,UnitFileState,FragmentPath "
	primaries := []string{
		"NetworkManager.service",
		"dhcpcd.service",
		"networking.service",
		"systemd-networkd.service",
	}
	for _, primary := range primaries {
		t.Run(primary, func(t *testing.T) {
			values := map[string][]byte{
				property + "NetworkManager.service":     loadedState("NetworkManager.service", "NetworkManager.service", "inactive", "disabled"),
				property + "dhcpcd.service":             loadedState("dhcpcd.service", "dhcpcd.service", "inactive", "disabled"),
				property + "dhcpcd@nftfw-probe.service": loadedState("dhcpcd@nftfw-probe.service", "dhcpcd@.service", "inactive", "static"),
				property + "ifup@nftfw-probe.service":   loadedState("ifup@nftfw-probe.service", "ifup@.service", "inactive", "static"),
				property + "networking.service":         loadedState("networking.service", "networking.service", "inactive", "disabled"),
				property + "systemd-networkd.service":   loadedState("systemd-networkd.service", "systemd-networkd.service", "inactive", "disabled"),
			}
			values[property+primary] = loadedState(primary, primary, "active", "enabled")
			units, err := Discover(context.Background(), fakeRunner{values: values})
			if err != nil {
				t.Fatal(err)
			}
			want := []string{
				"NetworkManager.service", "dhcpcd.service", "dhcpcd@.service",
				"ifup@.service", "networking.service", "systemd-networkd.service",
			}
			if !reflect.DeepEqual(units, want) {
				t.Fatalf("units=%v want=%v", units, want)
			}
		})
	}
}

func TestDiscoverRefusesEveryKnownUnsupportedManager(t *testing.T) {
	property := "systemctl show --property=Id,LoadState,ActiveState,UnitFileState,FragmentPath "
	for _, unit := range unsupported {
		t.Run(unit, func(t *testing.T) {
			runner := cleanRunner()
			runner.values[property+unit] = loadedState(unit, unit, "inactive", "disabled")
			_, err := Discover(context.Background(), runner)
			if err == nil || err.Error() != "SETUP_NETWORK_PRODUCER_UNSUPPORTED" {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestDiscoverRefusesAmbiguousUnsupportedAndUnsafeProducers(t *testing.T) {
	property := "systemctl show --property=Id,LoadState,ActiveState,UnitFileState,FragmentPath "
	tests := []struct {
		name string
		edit func(map[string][]byte)
		want string
	}{
		{"multiple-primary", func(values map[string][]byte) {
			values[property+"systemd-networkd.service"] = loadedState("systemd-networkd.service", "systemd-networkd.service", "active", "enabled")
		}, "SETUP_NETWORK_PRODUCER_AMBIGUOUS"},
		{"no-primary", func(values map[string][]byte) {
			values[property+"networking.service"] = loadedState("networking.service", "networking.service", "inactive", "disabled")
		}, "SETUP_NETWORK_PRODUCER_AMBIGUOUS"},
		{"unsupported", func(values map[string][]byte) {
			values[property+"connman.service"] = loadedState("connman.service", "connman.service", "inactive", "disabled")
		}, "SETUP_NETWORK_PRODUCER_UNSUPPORTED"},
		{"custom-fragment", func(values map[string][]byte) {
			values[property+"networking.service"] = []byte("Id=networking.service\nLoadState=loaded\nActiveState=active\nUnitFileState=enabled\nFragmentPath=/etc/systemd/system/networking.service\n")
		}, "SETUP_NETWORK_PRODUCER_UNSAFE"},
		{"duplicate-field", func(values map[string][]byte) {
			values[property+"networking.service"] = append(values[property+"networking.service"], []byte("Id=networking.service\n")...)
		}, "SETUP_NETWORK_PRODUCER_INSPECTION_FAILED"},
		{"missing-newline", func(values map[string][]byte) {
			values[property+"networking.service"] = []byte("Id=networking.service")
		}, "SETUP_NETWORK_PRODUCER_INSPECTION_FAILED"},
		{"oversized-observation", func(values map[string][]byte) {
			values[property+"networking.service"] = []byte(strings.Repeat("x", maxUnitOutput+1) + "\n")
		}, "SETUP_NETWORK_PRODUCER_INSPECTION_FAILED"},
		{"identity-mismatch", func(values map[string][]byte) {
			values[property+"networking.service"] = loadedState("other.service", "networking.service", "active", "enabled")
		}, "SETUP_NETWORK_PRODUCER_UNSAFE"},
		{"active-template", func(values map[string][]byte) {
			values[property+"ifup@nftfw-probe.service"] = loadedState("ifup@nftfw-probe.service", "ifup@.service", "active", "static")
		}, "SETUP_NETWORK_PRODUCER_UNSAFE"},
		{"masked-unit", func(values map[string][]byte) {
			values[property+"networking.service"] = loadedState("networking.service", "networking.service", "inactive", "masked")
		}, "SETUP_NETWORK_PRODUCER_UNSAFE"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := cleanRunner()
			test.edit(runner.values)
			_, err := Discover(context.Background(), runner)
			if err == nil || err.Error() != test.want {
				t.Fatalf("error=%v want=%s", err, test.want)
			}
		})
	}
}

func TestDropInAndMarkerValidationRejectTampering(t *testing.T) {
	root := t.TempDir()
	systemd := filepath.Join(root, "etc/systemd/system")
	units := []string{"ifup@.service", "networking.service"}
	paths, err := DropInPaths(systemd, units)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(DropInData), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := ValidateDropIn(path); err != nil {
			t.Fatalf("valid drop-in %s: %v", path, err)
		}
	}
	marker := filepath.Join(root, "etc/nftfw/setup-network-producers-v1")
	data, _ := BootMarkerData(units)
	if err := os.MkdirAll(filepath.Dir(marker), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(marker, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateBootMarker(marker, units); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths[0], []byte("[Unit]\nAfter=network-pre.target\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ValidateDropIn(paths[0]); err == nil {
		t.Fatal("tampered drop-in accepted")
	}
	if err := os.Chmod(marker, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := ValidateBootMarker(marker, units); err == nil {
		t.Fatal("unsafe marker mode accepted")
	}
}

func TestDropInTargetRejectsSymlinkedParentAndTarget(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	if err := os.Mkdir(realDir, 0o750); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "systemd")
	if err := os.Symlink(realDir, link); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(link, "networking.service.d", DropInName)
	if err := ValidateDropInTarget(path); err == nil {
		t.Fatal("symlinked parent accepted")
	}
	path = filepath.Join(root, "safe", "networking.service.d", DropInName)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target", path); err != nil {
		t.Fatal(err)
	}
	if err := ValidateDropInTarget(path); err == nil {
		t.Fatal("symlink target accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(DropInData), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := ValidateDropInTarget(path); err == nil {
		t.Fatal("group/world-writable target accepted")
	}
}

func TestBootMarkerTargetRefusesForeignType(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "etc/nftfw")
	if err := os.MkdirAll(parent, 0o750); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "setup-network-producers-v1")
	if err := ValidateBootMarkerTarget(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := ValidateBootMarkerTarget(path); err == nil {
		t.Fatal("directory marker target accepted")
	}
}

func TestVerifyEffectiveRequiresExactThreeEdges(t *testing.T) {
	root := t.TempDir()
	units := []string{"ifup@.service", "networking.service"}
	paths, err := DropInPaths(root, units)
	if err != nil {
		t.Fatal(err)
	}
	runner := fakeRunner{values: map[string][]byte{}}
	for index, unit := range units {
		if err := os.MkdirAll(filepath.Dir(paths[index]), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(paths[index], []byte(DropInData), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(paths[index], 0o644); err != nil {
			t.Fatal(err)
		}
		probe, _ := probeFor(unit)
		runner.values["systemctl show --property=Requires,BindsTo,After "+probe] =
			[]byte("Requires=nftfw-enforcement-ready.service\nBindsTo=nftfw-enforcement-ready.service\nAfter=network-pre.target nftfw-enforcement-ready.service\n")
	}
	if err := VerifyEffective(context.Background(), runner, root, units); err != nil {
		t.Fatal(err)
	}
	command := "systemctl show --property=Requires,BindsTo,After networking.service"
	invalid := map[string]string{
		"missing-requires": "Requires=\nBindsTo=nftfw-enforcement-ready.service\nAfter=nftfw-enforcement-ready.service\n",
		"missing-binds":    "Requires=nftfw-enforcement-ready.service\nBindsTo=\nAfter=nftfw-enforcement-ready.service\n",
		"missing-after":    "Requires=nftfw-enforcement-ready.service\nBindsTo=nftfw-enforcement-ready.service\nAfter=network-pre.target\n",
		"duplicate-edge":   "Requires=nftfw-enforcement-ready.service\nBindsTo=nftfw-enforcement-ready.service nftfw-enforcement-ready.service\nAfter=nftfw-enforcement-ready.service\n",
		"duplicate-key":    "Requires=nftfw-enforcement-ready.service\nBindsTo=nftfw-enforcement-ready.service\nBindsTo=nftfw-enforcement-ready.service\nAfter=nftfw-enforcement-ready.service\n",
	}
	for name, output := range invalid {
		t.Run(name, func(t *testing.T) {
			runner.values[command] = []byte(output)
			if err := VerifyEffective(context.Background(), runner, root, units); err == nil {
				t.Fatal("invalid effective dependency graph accepted")
			}
		})
	}
}

func TestExactFileValidationDetectsRenameDuringRead(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, DropInName)
	if err := os.WriteFile(path, []byte(DropInData), 0o644); err != nil {
		t.Fatal(err)
	}
	err := validateExactFileWithHook(
		path, []byte(DropInData), 0o644, "unsafe", "invalid", func() {
			replacement := filepath.Join(root, "replacement")
			if writeErr := os.WriteFile(replacement, []byte(DropInData), 0o644); writeErr != nil {
				t.Fatal(writeErr)
			}
			if renameErr := os.Rename(replacement, path); renameErr != nil {
				t.Fatal(renameErr)
			}
		},
	)
	if err == nil || err.Error() != "unsafe" {
		t.Fatalf("rename race accepted: %v", err)
	}
}

func TestHoldAndOperatorBackupDropInValidation(t *testing.T) {
	root := t.TempDir()
	units := []string{"ifup@.service", "networking.service"}
	generator := filepath.Join(root, "run/systemd/generator")
	for _, unit := range units {
		writeMode(t, filepath.Join(generator, unit+".d", HoldDropInName), []byte(HoldDropInData), 0o644)
	}
	if err := ValidateHoldDropIns(generator, units); err != nil {
		t.Fatal(err)
	}
	writeMode(t, filepath.Join(generator, "ifup@.service.d", HoldDropInName), []byte("foreign\n"), 0o644)
	if err := ValidateHoldDropIns(generator, units); err == nil {
		t.Fatal("foreign hold drop-in accepted")
	}

	backup := filepath.Join(root, "backup", DropInName)
	writeMode(t, backup, []byte(DropInData), 0o600)
	if err := ValidateBackupDropIn(backup); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(backup, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ValidateBackupDropIn(backup); err == nil {
		t.Fatal("public operator-backup gate accepted")
	}
}

func TestPathAndUnitBoundaryRefusals(t *testing.T) {
	root := t.TempDir()
	for _, units := range [][]string{
		nil,
		{"networking.service", "ifup@.service"},
		{"networking.service", "networking.service"},
		{"foreign.service"},
		{"NetworkManager.service", "dhcpcd.service", "dhcpcd@.service", "ifup@.service", "networking.service", "systemd-networkd.service", "foreign.service"},
	} {
		if err := ValidateUnits(units); err == nil {
			t.Fatalf("invalid unit set accepted: %v", units)
		}
		if _, err := DropInPaths(root, units); err == nil {
			t.Fatalf("invalid drop-in set accepted: %v", units)
		}
		if _, err := BootMarkerData(units); err == nil {
			t.Fatalf("invalid marker set accepted: %v", units)
		}
	}
	for _, test := range []struct {
		dir, unit string
	}{
		{"relative", "networking.service"},
		{"/", "networking.service"},
		{root, "foreign.service"},
	} {
		if _, err := DropInPath(test.dir, test.unit); err == nil {
			t.Fatalf("invalid drop-in path accepted: %#v", test)
		}
	}
	if err := ValidateHoldDropIns("relative", []string{"networking.service"}); err == nil {
		t.Fatal("relative generator directory accepted")
	}
	if err := ValidateBackupDropIn(filepath.Join(root, "wrong.conf")); err == nil {
		t.Fatal("wrong backup filename accepted")
	}
	if err := ValidateDropIn("relative"); err == nil {
		t.Fatal("relative final drop-in accepted")
	}
	if err := ValidateBackupDropIn("relative"); err == nil {
		t.Fatal("relative backup drop-in accepted")
	}
	if err := ValidateBootMarker("relative", []string{"networking.service"}); err == nil {
		t.Fatal("relative marker accepted")
	}
	if err := ValidateBootMarker(filepath.Join(root, "marker"), nil); err == nil {
		t.Fatal("invalid marker unit set accepted")
	}
	if err := ValidateBootMarkerTarget(filepath.Join(root, "wrong-marker")); err == nil {
		t.Fatal("wrong marker target accepted")
	}
	if err := VerifyEffective(context.Background(), nil, root, []string{"networking.service"}); err == nil {
		t.Fatal("nil effective-graph runner accepted")
	}
}

func TestStrictObservationAndStateEnumerations(t *testing.T) {
	for _, state := range []string{"active", "inactive", "activating", "deactivating", "reloading", "failed", "maintenance"} {
		if !allowedActiveState(state) {
			t.Fatalf("supported active state refused: %s", state)
		}
	}
	if allowedActiveState("unknown") {
		t.Fatal("unknown active state accepted")
	}
	for _, state := range []string{"enabled", "enabled-runtime", "disabled", "static", "indirect", "generated"} {
		if !allowedUnitFileState(state) {
			t.Fatalf("supported unit-file state refused: %s", state)
		}
	}
	if allowedUnitFileState("masked") {
		t.Fatal("masked unit-file state accepted")
	}
	property := "systemctl show --property=Id,LoadState,ActiveState,UnitFileState,FragmentPath "
	for name, output := range map[string][]byte{
		"unknown-field": []byte("Id=networking.service\nLoadState=loaded\nActiveState=active\nUnitFileState=enabled\nFragmentPath=/usr/lib/systemd/system/networking.service\nOther=value\n"),
		"malformed":     []byte("not-a-property\n"),
	} {
		t.Run(name, func(t *testing.T) {
			runner := fakeRunner{values: map[string][]byte{property + "networking.service": output}}
			if _, err := inspect(context.Background(), runner, "networking.service"); err == nil {
				t.Fatal("malformed unit observation accepted")
			}
		})
	}
}

func TestValidationFailureBranches(t *testing.T) {
	if _, err := Discover(context.Background(), nil); err == nil {
		t.Fatal("nil discovery runner accepted")
	}
	if _, err := Discover(context.Background(), fakeRunner{fail: "networking.service"}); err == nil {
		t.Fatal("failed discovery command accepted")
	}
	if _, err := DropInPaths("relative", []string{"networking.service"}); err == nil {
		t.Fatal("relative systemd directory accepted")
	}
	if _, ok := probeFor("foreign.service"); ok {
		t.Fatal("foreign probe accepted")
	}

	root := t.TempDir()
	dropIn := filepath.Join(root, "networking.service.d", DropInName)
	if err := os.MkdirAll(dropIn, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := ValidateDropInTarget(dropIn); err == nil {
		t.Fatal("directory drop-in target accepted")
	}
	if err := os.Remove(dropIn); err != nil {
		t.Fatal(err)
	}
	writeMode(t, dropIn, []byte(DropInData), 0o644)
	if err := ValidateDropIn(dropIn); err != nil {
		t.Fatal(err)
	}

	marker := filepath.Join(root, "etc/nftfw/setup-network-producers-v1")
	units := []string{"networking.service"}
	markerData, err := BootMarkerData(units)
	if err != nil {
		t.Fatal(err)
	}
	writeMode(t, marker, markerData, 0o600)
	if err := ValidateBootMarkerTarget(marker); err != nil {
		t.Fatal(err)
	}
	if err := ValidateBootMarker(marker, units); err != nil {
		t.Fatal(err)
	}
	writeMode(t, marker, []byte("foreign marker\n"), 0o600)
	if err := ValidateBootMarker(marker, units); err == nil {
		t.Fatal("foreign marker content accepted")
	}
	if err := os.Chmod(marker, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := ValidateBootMarkerTarget(marker); err == nil {
		t.Fatal("writable marker target accepted")
	}

	writeMode(t, dropIn, []byte(DropInData), 0o644)
	runner := fakeRunner{fail: "--property=Requires,BindsTo,After"}
	if err := VerifyEffective(context.Background(), runner, root, units); err == nil {
		t.Fatal("effective graph command failure accepted")
	}
	if err := os.Remove(dropIn); err != nil {
		t.Fatal(err)
	}
	if err := VerifyEffective(context.Background(), fakeRunner{}, root, units); err == nil {
		t.Fatal("missing final drop-in accepted")
	}
	if err := VerifyEffective(context.Background(), fakeRunner{}, root, nil); err == nil {
		t.Fatal("invalid effective graph unit set accepted")
	}
	for name, data := range map[string][]byte{
		"empty":           nil,
		"missing-newline": []byte("Requires=nftfw-enforcement-ready.service"),
		"unknown-key":     []byte("Other=nftfw-enforcement-ready.service\n"),
		"oversized":       []byte(strings.Repeat("x", maxUnitOutput+1) + "\n"),
	} {
		t.Run(name, func(t *testing.T) {
			if effectiveDependency(data) {
				t.Fatal("invalid dependency observation accepted")
			}
		})
	}
}
