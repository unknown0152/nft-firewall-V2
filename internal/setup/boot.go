package setup

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/unknown0152/nft-firewall-v2/internal/config"
	"github.com/unknown0152/nft-firewall-v2/internal/routing"
	"golang.org/x/sys/unix"
)

const (
	ManagedBootPolicy = "debian-grub-ipv6-disabled-v1"
	bootBackupSchema  = "nftfw.setup-boot-backup.v1"
	grubFragmentData  = "# Managed by NFT Firewall V2. Do not edit.\n" +
		"GRUB_CMDLINE_LINUX=\"${GRUB_CMDLINE_LINUX:+$GRUB_CMDLINE_LINUX }ipv6.disable=1\"\n"
	bootHoldMarkerData          = "nftfw.setup-boot-hold.v1\n"
	bootHoldReadyData           = "nftfw.setup-boot-hold-ready.v1\n"
	bootHoldReleaseData         = "nftfw.setup-boot-release.v1\n"
	dockerHoldReadyData         = "nftfw.setup-docker-hold-ready.v1\n"
	dockerHoldReleaseData       = "nftfw.setup-docker-release.v1\n"
	dockerServiceHoldDropInData = "[Unit]\nRequires=nftfw-setup-docker-hold.service\n" +
		"After=nftfw-setup-docker-hold.service\n"
	// docker.socket must pull the hold in, but must not order itself after the
	// indefinite hold: doing so blocks sockets.target and therefore basic.target.
	// Socket requests remain queued because docker.service retains the ordered
	// dependency and cannot start until the managed transaction releases it.
	dockerSocketHoldDropInData = "[Unit]\nRequires=nftfw-setup-docker-hold.service\n"
	resumeGuardFilename        = "resume-guard.nft"
)

var (
	kernelReleasePattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
	bootIDPattern              = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	bootDockerNamePattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
	bootDockerInterfacePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$`)
)

type bootObservation struct {
	BootID          string
	MountSHA256     string
	KernelSHA256    string
	GeneratedSHA256 string
	Prepared        bool
}

type bootBackup struct {
	Schema                  string `json:"schema"`
	PreBootID               string `json:"pre_boot_id"`
	MountSHA256             string `json:"mount_sha256"`
	KernelSHA256            string `json:"kernel_sha256"`
	InitialGeneratedSHA256  string `json:"initial_generated_sha256"`
	PreparedGeneratedSHA256 string `json:"prepared_generated_sha256,omitempty"`
	FragmentSHA256          string `json:"fragment_sha256,omitempty"`
	ResumeGuardSHA256       string `json:"resume_guard_sha256,omitempty"`
	// ResumeEndpointIPv4 is root-only transaction state. It prevents the
	// post-reboot pass from depending on DNS while the resume guard is active.
	// It is never copied into the public summary, journal, status, or errors.
	ResumeEndpointIPv4   []string               `json:"resume_endpoint_ipv4"`
	ResumeDockerPresent  bool                   `json:"resume_docker_present"`
	ResumeDockerClean    bool                   `json:"resume_docker_clean"`
	ResumeDockerNetworks []config.DockerNetwork `json:"resume_docker_networks"`
}

func validBootBackup(value bootBackup) bool {
	if value.Schema != bootBackupSchema || !bootIDPattern.MatchString(value.PreBootID) ||
		!validSHA256(value.MountSHA256) || !validSHA256(value.KernelSHA256) ||
		!validSHA256(value.InitialGeneratedSHA256) || !validResumeEndpoints(value.ResumeEndpointIPv4) ||
		!validResumeDockerState(value.ResumeDockerPresent, value.ResumeDockerClean, value.ResumeDockerNetworks) {
		return false
	}
	if (value.PreparedGeneratedSHA256 == "") != (value.FragmentSHA256 == "") ||
		value.ResumeGuardSHA256 != "" && !validSHA256(value.ResumeGuardSHA256) {
		return false
	}
	return value.PreparedGeneratedSHA256 == "" ||
		validSHA256(value.PreparedGeneratedSHA256) && validSHA256(value.FragmentSHA256) &&
			validSHA256(value.ResumeGuardSHA256)
}

func (o bootObservation) backup(endpoints []netip.Addr, dockerNetworks []config.DockerNetwork) *bootBackup {
	resumeEndpoints := make([]string, len(endpoints))
	for index, endpoint := range endpoints {
		resumeEndpoints[index] = endpoint.String()
	}
	resumeDocker := make([]config.DockerNetwork, len(dockerNetworks))
	for index, network := range dockerNetworks {
		resumeDocker[index] = network
		resumeDocker[index].Subnets = slices.Clone(network.Subnets)
		resumeDocker[index].Gateways = slices.Clone(network.Gateways)
	}
	if len(resumeDocker) == 0 {
		resumeDocker = nil
	}
	return &bootBackup{
		Schema: bootBackupSchema, PreBootID: o.BootID, MountSHA256: o.MountSHA256,
		KernelSHA256: o.KernelSHA256, InitialGeneratedSHA256: o.GeneratedSHA256,
		ResumeEndpointIPv4: resumeEndpoints, ResumeDockerPresent: len(resumeDocker) > 0,
		ResumeDockerClean: true, ResumeDockerNetworks: resumeDocker,
	}
}

func validResumeDockerState(present, clean bool, networks []config.DockerNetwork) bool {
	if !clean || present != (len(networks) > 0) || len(networks) > 256 ||
		!present && networks != nil {
		return false
	}
	names := map[string]bool{}
	bridges := map[string]bool{}
	var prefixes []netip.Prefix
	previousName := ""
	for _, network := range networks {
		if !bootDockerNamePattern.MatchString(network.Name) || names[network.Name] ||
			previousName != "" && previousName >= network.Name || network.Driver != "bridge" ||
			!network.DynamicBridge || !bootDockerInterfacePattern.MatchString(network.BridgeInterface) ||
			bridges[network.BridgeInterface] || len(network.Subnets) == 0 ||
			len(network.Subnets) > 16 || len(network.Subnets) != len(network.Gateways) {
			return false
		}
		names[network.Name], bridges[network.BridgeInterface], previousName = true, true, network.Name
		previousSubnet := ""
		for index, rawSubnet := range network.Subnets {
			prefix, err := netip.ParsePrefix(rawSubnet)
			if err != nil || !prefix.Addr().Is4() || prefix.Bits() < 1 || prefix.Bits() > 30 ||
				prefix.Masked().String() != rawSubnet || previousSubnet != "" && previousSubnet >= rawSubnet {
				return false
			}
			for _, prior := range prefixes {
				if prefix.Overlaps(prior) {
					return false
				}
			}
			gateway, err := netip.ParseAddr(network.Gateways[index])
			if err != nil || !gateway.Is4() || gateway.String() != network.Gateways[index] ||
				!prefix.Contains(gateway) || gateway == prefix.Addr() || gateway == lastBootIPv4(prefix) {
				return false
			}
			prefixes = append(prefixes, prefix)
			previousSubnet = rawSubnet
		}
	}
	return true
}

func lastBootIPv4(prefix netip.Prefix) netip.Addr {
	value := binary.BigEndian.Uint32(prefix.Addr().AsSlice())
	value |= ^uint32(0) >> prefix.Bits()
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], value)
	return netip.AddrFrom4(raw)
}

func validResumeEndpoints(values []string) bool {
	if len(values) == 0 || len(values) > 16 {
		return false
	}
	previous := netip.Addr{}
	for index, raw := range values {
		address, err := netip.ParseAddr(raw)
		if err != nil || !address.Is4() || address.IsUnspecified() || address.IsLoopback() ||
			address.IsMulticast() || address.IsLinkLocalUnicast() || address.String() != raw ||
			index > 0 && !previous.Less(address) {
			return false
		}
		previous = address
	}
	return true
}

func resumeEndpointAddresses(backup bootBackup) ([]netip.Addr, error) {
	if !validResumeEndpoints(backup.ResumeEndpointIPv4) {
		return nil, errors.New("SETUP_RESUME_STATE_INVALID")
	}
	result := make([]netip.Addr, len(backup.ResumeEndpointIPv4))
	for index, raw := range backup.ResumeEndpointIPv4 {
		result[index] = netip.MustParseAddr(raw)
	}
	return result, nil
}

func inspectManagedGRUB(ctx context.Context, runner routing.Runner, paths Paths, prepared bool) (bootObservation, error) {
	return inspectManagedGRUBState(ctx, runner, paths, prepared, prepared, true)
}

// inspectManagedGRUBRuntime verifies the prepared identity from the boot-hold
// service's ProtectSystem=strict mount namespace. The original transaction
// must have proved a writable local boot filesystem; this runtime view may be
// read-only only because systemd hardened the verifier itself.
func inspectManagedGRUBRuntime(ctx context.Context, runner routing.Runner, paths Paths) (bootObservation, error) {
	return inspectManagedGRUBState(ctx, runner, paths, true, true, false)
}

func inspectManagedGRUBState(
	ctx context.Context, runner routing.Runner, paths Paths, prepared, holdPrepared, requireWritable bool,
) (bootObservation, error) {
	if runner == nil || !fixedBootPaths(paths) {
		return bootObservation{}, errors.New("SETUP_BOOT_POLICY_UNSUPPORTED")
	}
	for _, conflict := range []string{paths.SystemdBootEntries, paths.UKIDir, paths.ExtlinuxDir, paths.AlternateGRUBDir} {
		if _, err := os.Lstat(conflict); err == nil || !errors.Is(err, os.ErrNotExist) {
			return bootObservation{}, errors.New("SETUP_BOOT_MANAGER_AMBIGUOUS")
		}
	}
	for _, directory := range []string{
		paths.GRUBSourceDir, filepath.Dir(paths.GRUBGenerated), paths.BootKernelDir,
	} {
		if err := requireBootDirectory(directory); err != nil {
			return bootObservation{}, err
		}
	}
	if err := requireBootRegular(paths.GRUBUpdate, 1, 4<<20, true); err != nil {
		return bootObservation{}, err
	}
	if output, err := runner.Run(ctx, nil, "dpkg-query", "--search", paths.GRUBUpdate); err != nil ||
		string(output) != "grub2-common: "+paths.GRUBUpdate+"\n" {
		return bootObservation{}, errors.New("SETUP_BOOT_COMMAND_UNOWNED")
	}
	if output, err := runner.Run(ctx, nil, "dpkg-query", "--show", "--showformat=${Status}\\n", "grub2-common"); err != nil ||
		string(output) != "install ok installed\n" {
		return bootObservation{}, errors.New("SETUP_BOOT_COMMAND_UNOWNED")
	}
	if err := verifyInstalledGRUBFamily(ctx, runner, paths); err != nil {
		return bootObservation{}, err
	}
	kernelRelease, err := runner.Run(ctx, nil, "uname", "-r")
	release := strings.TrimSpace(string(kernelRelease))
	if err != nil || !kernelReleasePattern.MatchString(release) {
		return bootObservation{}, errors.New("SETUP_BOOT_KERNEL_UNSUPPORTED")
	}
	kernelPath := filepath.Join(paths.BootKernelDir, "vmlinuz-"+release)
	if err := requireBootRegular(kernelPath, 1, 256<<20, false); err != nil {
		return bootObservation{}, errors.New("SETUP_BOOT_KERNEL_UNSUPPORTED")
	}
	kernelSHA, err := digestBootRegular(kernelPath, 256<<20)
	if err != nil {
		return bootObservation{}, errors.New("SETUP_BOOT_KERNEL_UNSUPPORTED")
	}
	mountSHA, err := inspectBootMount(ctx, runner, paths, requireWritable)
	if err != nil {
		return bootObservation{}, err
	}
	generated, generatedInfo, err := readBootRegular(paths.GRUBGenerated, 4<<20)
	if err != nil || !sameDevice(generatedInfo, filepath.Dir(paths.GRUBGenerated)) {
		return bootObservation{}, errors.New("SETUP_BOOT_CONFIG_UNSAFE")
	}
	if err := verifyGeneratedGRUB(generated, prepared, filepath.Base(kernelPath)); err != nil {
		return bootObservation{}, err
	}
	fragmentInfo, fragmentErr := os.Lstat(paths.GRUBFragment)
	if !prepared {
		if !errors.Is(fragmentErr, os.ErrNotExist) {
			return bootObservation{}, errors.New("SETUP_BOOT_FRAGMENT_FOREIGN")
		}
	} else {
		if fragmentErr != nil || !fragmentInfo.Mode().IsRegular() || fragmentInfo.Mode().Perm() != 0o600 {
			return bootObservation{}, errors.New("SETUP_BOOT_FRAGMENT_INVALID")
		}
		fragment, _, readErr := readBootRegular(paths.GRUBFragment, 4<<10)
		if readErr != nil || string(fragment) != grubFragmentData {
			return bootObservation{}, errors.New("SETUP_BOOT_FRAGMENT_INVALID")
		}
	}
	if err := verifyBootHoldMarker(paths.BootHoldMarker, holdPrepared); err != nil {
		return bootObservation{}, err
	}
	bootID, err := readBootID(paths.ProcBootID)
	if err != nil {
		return bootObservation{}, err
	}
	sum := sha256.Sum256(generated)
	return bootObservation{
		BootID: bootID, MountSHA256: mountSHA, KernelSHA256: kernelSHA,
		GeneratedSHA256: hex.EncodeToString(sum[:]), Prepared: prepared,
	}, nil
}

func fixedBootPaths(paths Paths) bool {
	values := []string{
		paths.GRUBFragment, paths.GRUBSourceDir, paths.GRUBGenerated, paths.GRUBUpdate,
		paths.BootKernelDir, paths.ProcCmdline, paths.ProcBootID, paths.IPv6DisableParam,
		paths.ProcIfInet6, paths.SystemdBootEntries, paths.UKIDir, paths.ExtlinuxDir,
		paths.AlternateGRUBDir,
		paths.EFIFirmwareDir, paths.EFIBootManager, paths.BootHoldMarker,
		paths.BootHoldReady, paths.BootHoldRelease,
	}
	for _, value := range values {
		if !filepath.IsAbs(value) || filepath.Clean(value) != value {
			return false
		}
	}
	return filepath.Dir(paths.GRUBFragment) == paths.GRUBSourceDir
}

func verifyInstalledGRUBFamily(ctx context.Context, runner routing.Runner, paths Paths) error {
	architecture, err := runner.Run(ctx, nil, "uname", "-m")
	arch := strings.TrimSpace(string(architecture))
	if err != nil || arch != "x86_64" && arch != "aarch64" && arch != "arm64" {
		return errors.New("SETUP_BOOT_ARCHITECTURE_UNSUPPORTED")
	}
	efi := false
	if info, statErr := os.Lstat(paths.EFIFirmwareDir); statErr == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || requireBootDirectory(paths.EFIFirmwareDir) != nil {
			return errors.New("SETUP_BOOT_MANAGER_AMBIGUOUS")
		}
		efi = true
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return errors.New("SETUP_BOOT_MANAGER_AMBIGUOUS")
	}
	packages := []string{"grub-pc", "grub-efi-amd64", "grub-efi-arm64"}
	installed := map[string]bool{}
	for _, name := range packages {
		output, queryErr := runner.Run(ctx, nil, "dpkg-query", "--show", "--showformat=${db:Status-Abbrev}\\n", name)
		installed[name] = queryErr == nil && string(output) == "ii \n"
	}
	want := "grub-pc"
	if efi && arch == "x86_64" {
		want = "grub-efi-amd64"
	} else if efi {
		want = "grub-efi-arm64"
	} else if arch != "x86_64" {
		return errors.New("SETUP_BOOT_MANAGER_AMBIGUOUS")
	}
	if !installed[want] {
		return errors.New("SETUP_BOOT_MANAGER_AMBIGUOUS")
	}
	for name, present := range installed {
		if name != want && present {
			return errors.New("SETUP_BOOT_MANAGER_AMBIGUOUS")
		}
	}
	if efi {
		if err := verifyEFIBootIdentity(ctx, runner, paths, arch); err != nil {
			return err
		}
	}
	return nil
}

func verifyEFIBootIdentity(ctx context.Context, runner routing.Runner, paths Paths, arch string) error {
	if err := requireBootRegular(paths.EFIBootManager, 1, 4<<20, true); err != nil {
		return errors.New("SETUP_EFI_BOOT_IDENTITY_UNSUPPORTED")
	}
	if output, err := runner.Run(ctx, nil, "dpkg-query", "--search", paths.EFIBootManager); err != nil ||
		string(output) != "efibootmgr: "+paths.EFIBootManager+"\n" {
		return errors.New("SETUP_EFI_BOOT_IDENTITY_UNSUPPORTED")
	}
	if output, err := runner.Run(ctx, nil, "dpkg-query", "--show", "--showformat=${Status}\\n", "efibootmgr"); err != nil ||
		string(output) != "install ok installed\n" {
		return errors.New("SETUP_EFI_BOOT_IDENTITY_UNSUPPORTED")
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	output, err := runner.Run(bounded, nil, paths.EFIBootManager, "-v")
	if err != nil || len(output) == 0 || len(output) > 1<<20 || verifyEFIBootOutput(output, arch) != nil {
		return errors.New("SETUP_EFI_BOOT_IDENTITY_UNSUPPORTED")
	}
	return nil
}

func verifyEFIBootOutput(data []byte, arch string) error {
	if bytes.IndexByte(data, 0) >= 0 || arch != "x86_64" && arch != "aarch64" && arch != "arm64" {
		return errors.New("invalid EFI boot identity")
	}
	lowerOutput := strings.ToLower(string(data))
	if strings.Contains(lowerOutput, "pxe") || strings.Contains(lowerOutput, "httpv") ||
		strings.Contains(lowerOutput, "/mac(") {
		return errors.New("EFI firmware networking is enabled")
	}
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	current, order, currentCount, orderCount := "", "", 0, 0
	entries := map[string]string{}
	for _, line := range lines {
		// A switch over exact singleton labels makes duplicate parser arms a
		// compile-time error while preserving fail-closed duplicate evidence.
		if label, value, found := strings.Cut(line, ": "); found {
			switch label {
			case "BootCurrent":
				current, currentCount = strings.TrimSpace(value), currentCount+1
			case "BootOrder":
				order, orderCount = strings.TrimSpace(value), orderCount+1
			case "BootNext":
				return errors.New("one-shot EFI boot override is active")
			}
		}
		if len(line) >= 9 && strings.HasPrefix(line, "Boot") {
			identifier := line[4:8]
			if !fourHexDigits(identifier) || line[8] != '*' && line[8] != ' ' {
				continue
			}
			if _, duplicate := entries[identifier]; duplicate {
				return errors.New("duplicate EFI boot entry")
			}
			entries[identifier] = line
		}
	}
	if currentCount != 1 || orderCount != 1 || !fourHexDigits(current) {
		return errors.New("missing EFI boot identity")
	}
	ordered := strings.Split(order, ",")
	if len(ordered) == 0 || ordered[0] != current {
		return errors.New("EFI boot order is not local-current first")
	}
	seen := map[string]bool{}
	for _, identifier := range ordered {
		if !fourHexDigits(identifier) || seen[identifier] {
			return errors.New("invalid EFI boot order")
		}
		seen[identifier] = true
	}
	for identifier := range seen {
		if _, exists := entries[identifier]; !exists {
			return errors.New("EFI boot order references an unavailable entry")
		}
	}
	entry, ok := entries[current]
	if !ok || entry[8] != '*' {
		return errors.New("current EFI boot entry is unavailable")
	}
	lowerCurrent := strings.ToLower(entry)
	wantLoader := "shimx64.efi"
	if arch == "aarch64" || arch == "arm64" {
		wantLoader = "shimaa64.efi"
	}
	if !strings.Contains(lowerCurrent, " debian") || !strings.Contains(lowerCurrent, "hd(") ||
		!strings.Contains(lowerCurrent, `file(\efi\debian\`+wantLoader+`)`) {
		return errors.New("current EFI boot entry is not Debian GRUB")
	}
	return nil
}

func fourHexDigits(value string) bool {
	if len(value) != 4 {
		return false
	}
	for _, character := range value {
		decimal := character >= '0' && character <= '9'
		upper := character >= 'A' && character <= 'F'
		lower := character >= 'a' && character <= 'f'
		if !decimal && !upper && !lower {
			return false
		}
	}
	return true
}

func requireBootDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return errors.New("SETUP_BOOT_DIRECTORY_UNSAFE")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(stat.Uid) != int64(os.Geteuid()) {
		return errors.New("SETUP_BOOT_DIRECTORY_UNSAFE")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return errors.New("SETUP_BOOT_DIRECTORY_UNSAFE")
	}
	return nil
}

func requireBootRegular(path string, min, max int64, executable bool) error {
	_, info, err := readBootRegular(path, max)
	if err != nil || info.Size() < min || executable && info.Mode().Perm()&0o111 == 0 {
		return errors.New("SETUP_BOOT_FILE_UNSAFE")
	}
	return nil
}

func readBootRegular(path string, limit int64) ([]byte, os.FileInfo, error) {
	return readBootRegularHook(path, limit, nil)
}

func readBootRegularHook(path string, limit int64, afterRead func()) ([]byte, os.FileInfo, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, errors.New("SETUP_BOOT_FILE_UNSAFE")
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0o022 != 0 ||
		before.Size() < 0 || before.Size() > limit {
		return nil, nil, errors.New("SETUP_BOOT_FILE_UNSAFE")
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || int64(stat.Uid) != int64(os.Geteuid()) || stat.Nlink != 1 {
		return nil, nil, errors.New("SETUP_BOOT_FILE_UNSAFE")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) != before.Size() || int64(len(data)) > limit {
		return nil, nil, errors.New("SETUP_BOOT_FILE_UNSAFE")
	}
	if afterRead != nil {
		afterRead()
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || after.Size() != before.Size() ||
		!after.ModTime().Equal(before.ModTime()) {
		return nil, nil, errors.New("SETUP_BOOT_FILE_CHANGED")
	}
	return data, before, nil
}

func digestBootRegular(path string, limit int64) (string, error) {
	data, _, err := readBootRegular(path, limit)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func sameDevice(info os.FileInfo, directory string) bool {
	directoryInfo, err := os.Lstat(directory)
	left, leftOK := info.Sys().(*syscall.Stat_t)
	right, rightOK := directoryInfo.Sys().(*syscall.Stat_t)
	return err == nil && leftOK && rightOK && left.Dev == right.Dev
}

func inspectBootMount(ctx context.Context, runner routing.Runner, paths Paths, requireWritable bool) (string, error) {
	data, err := runner.Run(ctx, nil, "findmnt", "--json", "--target", filepath.Dir(paths.GRUBGenerated),
		"--output", "SOURCE,FSTYPE,TARGET,OPTIONS")
	if err != nil || len(data) == 0 || len(data) > 16<<10 {
		return "", errors.New("SETUP_BOOT_MOUNT_UNSUPPORTED")
	}
	var result struct {
		Filesystems []struct {
			Source  string `json:"source"`
			FSType  string `json:"fstype"`
			Target  string `json:"target"`
			Options string `json:"options"`
		} `json:"filesystems"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil || decoder.Decode(&struct{}{}) != io.EOF || len(result.Filesystems) != 1 {
		return "", errors.New("SETUP_BOOT_MOUNT_UNSUPPORTED")
	}
	fs := result.Filesystems[0]
	if !strings.HasPrefix(fs.Source, "/dev/") || !filepath.IsAbs(fs.Target) ||
		fs.FSType == "" || remoteFilesystem(fs.FSType) {
		return "", errors.New("SETUP_BOOT_MOUNT_UNSUPPORTED")
	}
	options, readWrite, readOnly, validOptions := stableMountOptions(fs.Options)
	if !validOptions || requireWritable && !readWrite || !requireWritable && !readWrite && !readOnly {
		return "", errors.New("SETUP_BOOT_MOUNT_UNSUPPORTED")
	}
	relative, relErr := filepath.Rel(fs.Target, filepath.Dir(paths.GRUBGenerated))
	if relErr != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", errors.New("SETUP_BOOT_MOUNT_UNSUPPORTED")
	}
	// The transaction capability check above still requires rw. Exclude only
	// the namespace-local rw/ro and hardening-only permission projections from the durable identity so the
	// hardened boot verifier can compare the same source, filesystem, target,
	// and stable mount options from its intentionally read-only namespace.
	fs.Options = strings.Join(options, ",")
	canonical, _ := json.Marshal(fs)
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func stableMountOptions(value string) ([]string, bool, bool, bool) {
	seen := map[string]bool{}
	stable := []string{}
	readWrite, readOnly := false, false
	for _, option := range strings.Split(value, ",") {
		if option == "" || seen[option] {
			return nil, false, false, false
		}
		seen[option] = true
		switch option {
		case "rw":
			readWrite = true
		case "ro":
			readOnly = true
		case "nosuid", "nodev", "noexec":
			// systemd may add these restrictions only inside the verifier's
			// private mount namespace. They cannot weaken the underlying boot
			// storage and do not change its device/filesystem/target identity.
		default:
			stable = append(stable, option)
		}
	}
	if readWrite == readOnly {
		return nil, false, false, false
	}
	slices.Sort(stable)
	return stable, readWrite, readOnly, true
}

func remoteFilesystem(value string) bool {
	switch strings.ToLower(value) {
	case "nfs", "nfs4", "cifs", "smb3", "sshfs", "9p", "ceph", "glusterfs":
		return true
	default:
		return false
	}
}

func verifyGeneratedGRUB(data []byte, prepared bool, activeKernel string) error {
	if len(data) == 0 || len(data) > 4<<20 {
		return errors.New("SETUP_BOOT_CONFIG_INVALID")
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	entries, active := 0, false
	for scanner.Scan() {
		tokens, err := grubWords(scanner.Text())
		if err != nil {
			return errors.New("SETUP_BOOT_CONFIG_INVALID")
		}
		if len(tokens) < 2 || tokens[0] != "linux" && tokens[0] != "linuxefi" {
			continue
		}
		entries++
		if filepath.Base(tokens[1]) == activeKernel {
			active = true
		}
		count := 0
		for _, argument := range tokens[2:] {
			if argument == "ipv6.disable=1" {
				count++
				continue
			}
			if argument == "ipv6.disable" || strings.HasPrefix(argument, "ipv6.disable=") {
				return errors.New("SETUP_BOOT_IPV6_ARGUMENT_CONFLICT")
			}
		}
		if prepared && count != 1 || !prepared && count != 0 {
			return errors.New("SETUP_BOOT_IPV6_ARGUMENT_INVALID")
		}
	}
	if scanner.Err() != nil || entries == 0 || !active {
		return errors.New("SETUP_BOOT_CONFIG_INVALID")
	}
	return nil
}

func grubWords(line string) ([]string, error) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil, nil
	}
	var words []string
	var current strings.Builder
	quote, escaped, started := rune(0), false, false
	flush := func() {
		if started {
			words = append(words, current.String())
			current.Reset()
			started = false
		}
	}
	for _, character := range line {
		if escaped {
			current.WriteRune(character)
			escaped, started = false, true
			continue
		}
		if character == '\\' && quote != '\'' {
			escaped, started = true, true
			continue
		}
		if quote != 0 {
			if character == quote {
				quote = 0
			} else {
				current.WriteRune(character)
			}
			started = true
			continue
		}
		switch character {
		case '\'', '"':
			quote, started = character, true
		case ' ', '\t':
			flush()
		default:
			current.WriteRune(character)
			started = true
		}
	}
	if quote != 0 || escaped {
		return nil, errors.New("invalid GRUB token quoting")
	}
	flush()
	return words, nil
}

func readBootID(path string) (string, error) {
	data, err := readProcFile(path, 128)
	value := strings.TrimSpace(string(data))
	if err != nil || !bootIDPattern.MatchString(value) {
		return "", errors.New("SETUP_BOOT_ID_INVALID")
	}
	return value, nil
}

func readProcFile(path string, limit int64) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("SETUP_BOOT_RUNTIME_PROOF_MISSING")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("SETUP_BOOT_RUNTIME_PROOF_INVALID")
	}
	return data, nil
}

func verifyRunningBoot(paths Paths, preBootID string) error {
	currentID, err := readBootID(paths.ProcBootID)
	if err != nil || currentID == preBootID {
		return errors.New("SETUP_REBOOT_NOT_OBSERVED")
	}
	cmdline, err := readProcFile(paths.ProcCmdline, 64<<10)
	if err != nil || bytes.IndexByte(cmdline, 0) >= 0 {
		return errors.New("SETUP_BOOT_RUNTIME_PROOF_INVALID")
	}
	count := 0
	for _, argument := range strings.Fields(string(cmdline)) {
		if argument == "ipv6.disable=1" {
			count++
		} else if argument == "ipv6.disable" || strings.HasPrefix(argument, "ipv6.disable=") ||
			strings.Contains(argument, "ipv6.disable=1") {
			return errors.New("SETUP_BOOT_RUNTIME_PROOF_INVALID")
		}
	}
	if count != 1 {
		return errors.New("SETUP_BOOT_RUNTIME_PROOF_INVALID")
	}
	parameter, err := readProcFile(paths.IPv6DisableParam, 32)
	if err != nil || func(value string) bool { return value != "Y" && value != "1" }(strings.TrimSpace(string(parameter))) {
		return errors.New("SETUP_BOOT_RUNTIME_PROOF_INVALID")
	}
	if err := verifyNoIPv6AddressState(paths.ProcIfInet6); err != nil {
		return errors.New("SETUP_BOOT_IPV6_STATE_PRESENT")
	}
	return nil
}

// A kernel booted with ipv6.disable=1 may omit /proc/net/if_inet6 entirely;
// other kernels retain it as an empty file. Both are an exact absence of IPv6
// address state after the command-line and module-parameter proofs above. An
// unreadable, linked, oversized, or nonempty path remains fail closed.
func verifyNoIPv6AddressState(path string) error {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errors.New("SETUP_BOOT_IPV6_STATE_INVALID")
	}
	defer file.Close()
	addresses, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil || len(addresses) > 1<<20 || len(bytes.TrimSpace(addresses)) != 0 {
		return errors.New("SETUP_BOOT_IPV6_STATE_INVALID")
	}
	return nil
}

func runningKernelHasManagedDisable(paths Paths) bool {
	cmdline, err := readProcFile(paths.ProcCmdline, 64<<10)
	if err != nil {
		return true
	}
	count := 0
	for _, argument := range strings.Fields(string(cmdline)) {
		if argument == "ipv6.disable=1" {
			count++
		} else if argument == "ipv6.disable" || strings.HasPrefix(argument, "ipv6.disable=") ||
			strings.Contains(argument, "ipv6.disable=1") {
			return true
		}
	}
	return count == 1
}

func preparedPlanSHA256(plan Plan, private *prepared) (string, error) {
	summary, err := json.Marshal(plan.Summary)
	if err != nil {
		return "", errors.New("SETUP_PREPARED_IDENTITY_FAILED")
	}
	hash := sha256.New()
	for _, field := range [][]byte{
		summary, private.IntentData, private.ConfigData, private.VPNData, private.GuardData,
		private.SysctlData, private.DockerData, private.PolicyData, []byte(private.Route.Interface),
		[]byte(private.Route.Uplink), []byte(private.Route.Fwmark), []byte(private.Route.Resolver),
	} {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(field)))
		_, _ = hash.Write(size[:])
		_, _ = hash.Write(field)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func publishGRUBFragment(path string) error {
	parent := filepath.Dir(path)
	temporary, err := os.CreateTemp(parent, ".nftfw-grub-*.tmp")
	if err != nil {
		return errors.New("SETUP_BOOT_FRAGMENT_CREATE_FAILED")
	}
	temporaryPath := temporary.Name()
	ok := false
	defer func() {
		_ = temporary.Close()
		if !ok {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return errors.New("SETUP_BOOT_FRAGMENT_CREATE_FAILED")
	}
	if _, err := temporary.WriteString(grubFragmentData); err != nil || temporary.Sync() != nil || temporary.Close() != nil {
		return errors.New("SETUP_BOOT_FRAGMENT_SYNC_FAILED")
	}
	if err := unix.Renameat2(unix.AT_FDCWD, temporaryPath, unix.AT_FDCWD, path, unix.RENAME_NOREPLACE); err != nil {
		if errors.Is(err, syscall.EEXIST) {
			return errors.New("SETUP_BOOT_FRAGMENT_FOREIGN")
		}
		return errors.New("SETUP_BOOT_FRAGMENT_PUBLISH_FAILED")
	}
	if err := syncRegularSetupFile(path); err != nil || syncSetupDirectory(parent) != nil {
		return errors.New("SETUP_BOOT_FRAGMENT_SYNC_FAILED")
	}
	ok = true
	return nil
}

func verifyBootHoldMarker(path string, prepared bool) error {
	info, err := os.Lstat(path)
	if !prepared {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return errors.New("SETUP_BOOT_HOLD_FOREIGN")
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return errors.New("SETUP_BOOT_HOLD_INVALID")
	}
	data, _, readErr := readBootRegular(path, 4<<10)
	if readErr != nil || string(data) != bootHoldMarkerData {
		return errors.New("SETUP_BOOT_HOLD_INVALID")
	}
	return nil
}

func publishBootHoldMarker(path string) error {
	parent := filepath.Dir(path)
	temporary, err := os.CreateTemp(parent, ".nftfw-boot-hold-*.tmp")
	if err != nil {
		return errors.New("SETUP_BOOT_HOLD_CREATE_FAILED")
	}
	temporaryPath := temporary.Name()
	ok := false
	defer func() {
		_ = temporary.Close()
		if !ok {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return errors.New("SETUP_BOOT_HOLD_CREATE_FAILED")
	}
	if _, err := temporary.WriteString(bootHoldMarkerData); err != nil || temporary.Sync() != nil || temporary.Close() != nil {
		return errors.New("SETUP_BOOT_HOLD_SYNC_FAILED")
	}
	if err := unix.Renameat2(unix.AT_FDCWD, temporaryPath, unix.AT_FDCWD, path, unix.RENAME_NOREPLACE); err != nil {
		if errors.Is(err, syscall.EEXIST) {
			return errors.New("SETUP_BOOT_HOLD_FOREIGN")
		}
		return errors.New("SETUP_BOOT_HOLD_PUBLISH_FAILED")
	}
	if err := syncRegularSetupFile(path); err != nil || syncSetupDirectory(parent) != nil {
		return errors.New("SETUP_BOOT_HOLD_SYNC_FAILED")
	}
	ok = true
	return nil
}

func publishResumeGuard(directory string, data []byte) (string, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory ||
		len(data) == 0 || len(data) > 1<<20 {
		return "", errors.New("SETUP_RESUME_GUARD_BACKUP_INVALID")
	}
	path := filepath.Join(directory, resumeGuardFilename)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return "", errors.New("SETUP_RESUME_GUARD_BACKUP_CREATE_FAILED")
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if file.Chmod(0o600) != nil {
		return "", errors.New("SETUP_RESUME_GUARD_BACKUP_SYNC_FAILED")
	}
	if _, err := file.Write(data); err != nil || file.Sync() != nil || file.Close() != nil ||
		syncSetupDirectory(directory) != nil {
		return "", errors.New("SETUP_RESUME_GUARD_BACKUP_SYNC_FAILED")
	}
	sum := sha256.Sum256(data)
	ok = true
	return hex.EncodeToString(sum[:]), nil
}

func readResumeGuard(directory string, manifest backupManifest) ([]byte, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory ||
		manifest.Path != directory || manifest.Boot == nil ||
		!validSHA256(manifest.Boot.ResumeGuardSHA256) {
		return nil, errors.New("SETUP_RESUME_GUARD_BACKUP_INVALID")
	}
	path := filepath.Join(directory, resumeGuardFilename)
	data, info, err := readBootRegular(path, 1<<20)
	if err != nil || info.Mode().Perm() != 0o600 || len(data) == 0 {
		return nil, errors.New("SETUP_RESUME_GUARD_BACKUP_INVALID")
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != manifest.Boot.ResumeGuardSHA256 {
		return nil, errors.New("SETUP_RESUME_GUARD_BACKUP_INVALID")
	}
	return data, nil
}

func runGRUBUpdate(ctx context.Context, runner routing.Runner, command string) error {
	const timeout = 2 * time.Minute
	type timedRunner interface {
		RunWithTimeout(context.Context, []byte, time.Duration, string, ...string) ([]byte, error)
	}
	var (
		output []byte
		err    error
	)
	if bounded, ok := runner.(timedRunner); ok {
		output, err = bounded.RunWithTimeout(ctx, nil, timeout, command)
	} else {
		updateCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		output, err = runner.Run(updateCtx, nil, command)
		if updateCtx.Err() != nil {
			err = updateCtx.Err()
		}
	}
	if err != nil || len(output) > 1<<20 {
		return errors.New("SETUP_BOOT_UPDATE_FAILED")
	}
	return nil
}

func sameInitialBoot(left bootObservation, right bootBackup) bool {
	return left.BootID == right.PreBootID && left.MountSHA256 == right.MountSHA256 &&
		left.KernelSHA256 == right.KernelSHA256 &&
		left.GeneratedSHA256 == right.InitialGeneratedSHA256 && !left.Prepared
}

func verifyPreparedBoot(observation bootObservation, record bootBackup) bool {
	return observation.Prepared && observation.MountSHA256 == record.MountSHA256 &&
		observation.KernelSHA256 == record.KernelSHA256 &&
		observation.GeneratedSHA256 == record.PreparedGeneratedSHA256 &&
		record.FragmentSHA256 == fmt.Sprintf("%x", sha256.Sum256([]byte(grubFragmentData)))
}
