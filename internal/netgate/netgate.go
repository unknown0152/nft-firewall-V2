// Package netgate inventories and owns the exact systemd dependency boundary
// between supported host network producers and NFTFW enforcement readiness.
package netgate

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

const (
	DropInName     = "50-nftfw-enforcement-ready.conf"
	HoldDropInName = "50-nftfw-setup-hold.conf"
	DropInData     = `[Unit]
Requires=nftfw-enforcement-ready.service
BindsTo=nftfw-enforcement-ready.service
After=nftfw-enforcement-ready.service
`
	HoldDropInData = `[Unit]
Requires=nftfw-setup-boot-hold.service
After=nftfw-setup-boot-hold.service
`
	bootMarkerHeader = "nftfw.setup-network-producers.v1"
	maxUnitOutput    = 4096
)

type Runner interface {
	Run(context.Context, []byte, string, ...string) ([]byte, error)
}

type unitSpec struct {
	unit    string
	probe   string
	primary bool
}

// The supported set is deliberately closed. These are the Debian 13 service
// entry points that directly own IPv4 interface configuration or DHCP for the
// managed clean-host contract. Template units are inspected through an inert,
// nonexistent interface instance because systemctl does not accept bare
// template names for property inspection.
var supported = []unitSpec{
	{unit: "NetworkManager.service", probe: "NetworkManager.service", primary: true},
	{unit: "dhcpcd.service", probe: "dhcpcd.service", primary: true},
	{unit: "dhcpcd@.service", probe: "dhcpcd@nftfw-probe.service"},
	{unit: "ifup@.service", probe: "ifup@nftfw-probe.service"},
	{unit: "networking.service", probe: "networking.service", primary: true},
	{unit: "systemd-networkd.service", probe: "systemd-networkd.service", primary: true},
}

// Known alternate network managers are refused rather than silently treated
// as inert. Supporting one requires an explicit source change and boot test.
var unsupported = []string{
	"connman.service",
	"netctl.service",
	"wicked.service",
	"wicd.service",
}

type observedUnit struct {
	ID, LoadState, ActiveState, UnitFileState, FragmentPath string
}

// Discover returns the sorted, immutable set of supported producer units that
// must be gated. It rejects custom fragments, known alternate managers, and
// multiple enabled/active primary managers before setup can mutate the host.
func Discover(ctx context.Context, runner Runner) ([]string, error) {
	if runner == nil {
		return nil, errors.New("SETUP_NETWORK_PRODUCER_INSPECTION_FAILED")
	}
	var result []string
	selectedPrimary := 0
	for _, spec := range supported {
		observed, err := inspect(ctx, runner, spec.probe)
		if err != nil {
			return nil, errors.New("SETUP_NETWORK_PRODUCER_INSPECTION_FAILED")
		}
		if absent(observed, spec.probe) {
			continue
		}
		if observed.ID != spec.probe || observed.LoadState != "loaded" ||
			!allowedActiveState(observed.ActiveState) ||
			!allowedUnitFileState(observed.UnitFileState) ||
			!canonicalVendorPath(observed.FragmentPath, spec.unit) {
			return nil, errors.New("SETUP_NETWORK_PRODUCER_UNSAFE")
		}
		if strings.Contains(spec.unit, "@.") && observed.ActiveState != "inactive" {
			return nil, errors.New("SETUP_NETWORK_PRODUCER_UNSAFE")
		}
		result = append(result, spec.unit)
		if spec.primary && (observed.ActiveState == "active" ||
			observed.UnitFileState == "enabled" || observed.UnitFileState == "enabled-runtime") {
			selectedPrimary++
		}
	}
	for _, unit := range unsupported {
		observed, err := inspect(ctx, runner, unit)
		if err != nil {
			return nil, errors.New("SETUP_NETWORK_PRODUCER_INSPECTION_FAILED")
		}
		if !absent(observed, unit) {
			return nil, errors.New("SETUP_NETWORK_PRODUCER_UNSUPPORTED")
		}
	}
	if selectedPrimary != 1 || len(result) == 0 {
		return nil, errors.New("SETUP_NETWORK_PRODUCER_AMBIGUOUS")
	}
	sort.Strings(result)
	return result, nil
}

func inspect(ctx context.Context, runner Runner, unit string) (observedUnit, error) {
	data, err := runner.Run(ctx, nil, "systemctl", "show",
		"--property=Id,LoadState,ActiveState,UnitFileState,FragmentPath", unit)
	if err != nil || len(data) == 0 || len(data) > maxUnitOutput || !bytes.HasSuffix(data, []byte("\n")) {
		return observedUnit{}, errors.New("invalid unit observation")
	}
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || strings.ContainsAny(value, "\r\n") {
			return observedUnit{}, errors.New("invalid unit observation")
		}
		switch key {
		case "Id", "LoadState", "ActiveState", "UnitFileState", "FragmentPath":
			if _, duplicate := values[key]; duplicate {
				return observedUnit{}, errors.New("invalid unit observation")
			}
			values[key] = value
		default:
			return observedUnit{}, errors.New("invalid unit observation")
		}
	}
	for _, key := range []string{"Id", "LoadState", "ActiveState", "UnitFileState", "FragmentPath"} {
		if _, present := values[key]; !present {
			return observedUnit{}, errors.New("invalid unit observation")
		}
	}
	return observedUnit{
		ID: values["Id"], LoadState: values["LoadState"], ActiveState: values["ActiveState"],
		UnitFileState: values["UnitFileState"], FragmentPath: values["FragmentPath"],
	}, nil
}

func absent(observed observedUnit, probe string) bool {
	return observed.ID == probe && observed.LoadState == "not-found" &&
		observed.ActiveState == "inactive" && observed.UnitFileState == "" &&
		observed.FragmentPath == ""
}

func canonicalVendorPath(path, unit string) bool {
	return path == "/usr/lib/systemd/system/"+unit || path == "/lib/systemd/system/"+unit
}

func allowedActiveState(value string) bool {
	switch value {
	case "active", "inactive", "activating", "deactivating", "reloading", "failed", "maintenance":
		return true
	default:
		return false
	}
}

func allowedUnitFileState(value string) bool {
	switch value {
	case "enabled", "enabled-runtime", "disabled", "static", "indirect", "generated":
		return true
	default:
		return false
	}
}

// ValidateUnits rejects any journal or marker set that is not a canonical,
// sorted subset of the closed supported list.
func ValidateUnits(units []string) error {
	if len(units) == 0 || len(units) > len(supported) {
		return errors.New("SETUP_NETWORK_PRODUCER_SET_INVALID")
	}
	allowed := map[string]bool{}
	for _, spec := range supported {
		allowed[spec.unit] = true
	}
	previous := ""
	for _, unit := range units {
		if !allowed[unit] || previous != "" && previous >= unit {
			return errors.New("SETUP_NETWORK_PRODUCER_SET_INVALID")
		}
		previous = unit
	}
	return nil
}

func DropInPath(systemdDir, unit string) (string, error) {
	if !filepath.IsAbs(systemdDir) || filepath.Clean(systemdDir) != systemdDir ||
		systemdDir == "/" || ValidateUnits([]string{unit}) != nil {
		return "", errors.New("SETUP_NETWORK_PRODUCER_PATH_INVALID")
	}
	return filepath.Join(systemdDir, unit+".d", DropInName), nil
}

func DropInPaths(systemdDir string, units []string) ([]string, error) {
	if err := ValidateUnits(units); err != nil {
		return nil, err
	}
	result := make([]string, len(units))
	for index, unit := range units {
		path, err := DropInPath(systemdDir, unit)
		if err != nil {
			return nil, err
		}
		result[index] = path
	}
	return result, nil
}

func ValidateHoldDropIns(generatorDir string, units []string) error {
	if !filepath.IsAbs(generatorDir) || filepath.Clean(generatorDir) != generatorDir ||
		ValidateUnits(units) != nil {
		return errors.New("SETUP_NETWORK_PRODUCER_HOLD_INVALID")
	}
	for _, unit := range units {
		path := filepath.Join(generatorDir, unit+".d", HoldDropInName)
		if err := validateProtectedParent(path); err != nil ||
			validateExactFile(path, []byte(HoldDropInData), 0o644,
				"SETUP_NETWORK_PRODUCER_HOLD_UNSAFE", "SETUP_NETWORK_PRODUCER_HOLD_INVALID") != nil {
			return errors.New("SETUP_NETWORK_PRODUCER_HOLD_INVALID")
		}
	}
	return nil
}

func BootMarkerData(units []string) ([]byte, error) {
	if err := ValidateUnits(units); err != nil {
		return nil, err
	}
	return []byte(bootMarkerHeader + "\n" + strings.Join(units, "\n") + "\n"), nil
}

func ValidateDropInTarget(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) != DropInName {
		return errors.New("SETUP_NETWORK_PRODUCER_DROPIN_PATH_INVALID")
	}
	if err := validateProtectedParent(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o022 != 0 {
		return errors.New("SETUP_NETWORK_PRODUCER_DROPIN_UNSAFE")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(stat.Uid) != int64(os.Geteuid()) {
		return errors.New("SETUP_NETWORK_PRODUCER_DROPIN_UNSAFE")
	}
	return nil
}

func ValidateDropIn(path string) error {
	if err := ValidateDropInTarget(path); err != nil {
		return err
	}
	return validateExactFile(path, []byte(DropInData), 0o644,
		"SETUP_NETWORK_PRODUCER_DROPIN_UNSAFE", "SETUP_NETWORK_PRODUCER_DROPIN_INVALID")
}

// ValidateBackupDropIn validates the same exact dependency content after an
// operator backup has deliberately normalized private bundle files to 0600.
func ValidateBackupDropIn(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) != DropInName {
		return errors.New("SETUP_NETWORK_PRODUCER_DROPIN_PATH_INVALID")
	}
	if err := validateProtectedParent(path); err != nil {
		return err
	}
	return validateExactFile(path, []byte(DropInData), 0o600,
		"SETUP_NETWORK_PRODUCER_DROPIN_UNSAFE", "SETUP_NETWORK_PRODUCER_DROPIN_INVALID")
}

func ValidateBootMarker(path string, units []string) error {
	data, err := BootMarkerData(units)
	if err != nil {
		return err
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("SETUP_NETWORK_PRODUCER_MARKER_INVALID")
	}
	if err := validateProtectedParent(path); err != nil {
		return errors.New("SETUP_NETWORK_PRODUCER_MARKER_UNSAFE")
	}
	return validateExactFile(path, data, 0o600,
		"SETUP_NETWORK_PRODUCER_MARKER_UNSAFE", "SETUP_NETWORK_PRODUCER_MARKER_INVALID")
}

func ValidateBootMarkerTarget(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path ||
		filepath.Base(path) != "setup-network-producers-v1" {
		return errors.New("SETUP_NETWORK_PRODUCER_MARKER_INVALID")
	}
	if err := validateProtectedParent(path); err != nil {
		return errors.New("SETUP_NETWORK_PRODUCER_MARKER_UNSAFE")
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o022 != 0 {
		return errors.New("SETUP_NETWORK_PRODUCER_MARKER_UNSAFE")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(stat.Uid) != int64(os.Geteuid()) {
		return errors.New("SETUP_NETWORK_PRODUCER_MARKER_UNSAFE")
	}
	return nil
}

func validateExactFile(path string, expected []byte, mode os.FileMode, unsafeCode, invalidCode string) error {
	return validateExactFileWithHook(path, expected, mode, unsafeCode, invalidCode, nil)
}

func validateExactFileWithHook(
	path string, expected []byte, mode os.FileMode, unsafeCode, invalidCode string, afterRead func(),
) error {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 ||
		before.Mode().Perm() != mode || before.Size() != int64(len(expected)) {
		return errors.New(unsafeCode)
	}
	beforeStat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || int64(beforeStat.Uid) != int64(os.Geteuid()) {
		return errors.New(unsafeCode)
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return errors.New(unsafeCode)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, int64(len(expected))+1))
	if afterRead != nil {
		afterRead()
	}
	after, statErr := file.Stat()
	closeErr := file.Close()
	if readErr != nil || statErr != nil || closeErr != nil {
		return errors.New(unsafeCode)
	}
	afterStat, statOK := after.Sys().(*syscall.Stat_t)
	current, currentErr := os.Lstat(path)
	currentStat, currentOK := func() (*syscall.Stat_t, bool) {
		if currentErr != nil {
			return nil, false
		}
		value, ok := current.Sys().(*syscall.Stat_t)
		return value, ok
	}()
	if !statOK ||
		beforeStat.Dev != afterStat.Dev || beforeStat.Ino != afterStat.Ino ||
		before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) ||
		!currentOK || currentStat.Dev != afterStat.Dev || currentStat.Ino != afterStat.Ino {
		return errors.New(unsafeCode)
	}
	if !bytes.Equal(data, expected) {
		return errors.New(invalidCode)
	}
	return nil
}

func validateProtectedParent(path string) error {
	existing := filepath.Dir(path)
	for {
		info, err := os.Lstat(existing)
		if err == nil {
			resolved, resolveErr := filepath.EvalSymlinks(existing)
			if resolveErr != nil || resolved != existing || !info.IsDir() ||
				info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
				return errors.New("SETUP_NETWORK_PRODUCER_PARENT_UNSAFE")
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || int64(stat.Uid) != int64(os.Geteuid()) {
				return errors.New("SETUP_NETWORK_PRODUCER_PARENT_UNSAFE")
			}
			return nil
		}
		if !errors.Is(err, os.ErrNotExist) || existing == filepath.Dir(existing) {
			return errors.New("SETUP_NETWORK_PRODUCER_PARENT_UNSAFE")
		}
		existing = filepath.Dir(existing)
	}
}

// VerifyEffective proves both the exact owned files and systemd's effective
// Requires/BindsTo/After graph after daemon-reload. A template is verified through the
// same inert probe instance used during discovery.
func VerifyEffective(ctx context.Context, runner Runner, systemdDir string, units []string) error {
	paths, err := DropInPaths(systemdDir, units)
	if err != nil || runner == nil {
		return errors.New("SETUP_NETWORK_PRODUCER_VERIFY_FAILED")
	}
	for index, unit := range units {
		if err := ValidateDropIn(paths[index]); err != nil {
			return errors.New("SETUP_NETWORK_PRODUCER_VERIFY_FAILED")
		}
		probe, ok := probeFor(unit)
		if !ok {
			return errors.New("SETUP_NETWORK_PRODUCER_VERIFY_FAILED")
		}
		data, runErr := runner.Run(ctx, nil, "systemctl", "show", "--property=Requires,BindsTo,After", probe)
		if runErr != nil || !effectiveDependency(data) {
			return errors.New("SETUP_NETWORK_PRODUCER_VERIFY_FAILED")
		}
	}
	return nil
}

func effectiveDependency(data []byte) bool {
	if len(data) == 0 || len(data) > maxUnitOutput || !bytes.HasSuffix(data, []byte("\n")) {
		return false
	}
	values := map[string][]string{}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || (key != "Requires" && key != "BindsTo" && key != "After") || seen[key] {
			return false
		}
		seen[key] = true
		values[key] = strings.Fields(value)
	}
	for _, key := range []string{"Requires", "BindsTo", "After"} {
		if !seen[key] {
			return false
		}
		found := 0
		for _, dependency := range values[key] {
			if dependency == "nftfw-enforcement-ready.service" {
				found++
			}
		}
		if found != 1 {
			return false
		}
	}
	return true
}

func probeFor(unit string) (string, bool) {
	for _, spec := range supported {
		if spec.unit == unit {
			return spec.probe, true
		}
	}
	return "", false
}
