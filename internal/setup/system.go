package setup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/unknown0152/nft-firewall-v2/internal/api"
	"github.com/unknown0152/nft-firewall-v2/internal/bootguard"
	"github.com/unknown0152/nft-firewall-v2/internal/compiler"
	"github.com/unknown0152/nft-firewall-v2/internal/config"
	"github.com/unknown0152/nft-firewall-v2/internal/containers"
	"github.com/unknown0152/nft-firewall-v2/internal/discovery"
	"github.com/unknown0152/nft-firewall-v2/internal/health"
	"github.com/unknown0152/nft-firewall-v2/internal/intent"
	"github.com/unknown0152/nft-firewall-v2/internal/policy"
	"github.com/unknown0152/nft-firewall-v2/internal/reconcile"
	"github.com/unknown0152/nft-firewall-v2/internal/routing"
	"github.com/unknown0152/nft-firewall-v2/internal/wgconfig"
)

type Paths struct {
	Config             string
	Intent             string
	VPN                string
	Sysctl             string
	StateDir           string
	RuntimeDir         string
	SystemdDir         string
	DockerDaemon       string
	DockerDropIn       string
	InitramfsMarker    string
	InitramfsOwner     string
	InitramfsLoader    string
	InitramfsGate      string
	InitramfsManager   string
	GRUBFragment       string
	GRUBSourceDir      string
	GRUBGenerated      string
	GRUBUpdate         string
	BootKernelDir      string
	ProcCmdline        string
	ProcBootID         string
	IPv6DisableParam   string
	ProcIfInet6        string
	SystemdBootEntries string
	UKIDir             string
	ExtlinuxDir        string
	AlternateGRUBDir   string
	EFIFirmwareDir     string
	EFIBootManager     string
	BootHoldMarker     string
	BootHoldReady      string
	BootHoldRelease    string
	DockerHoldReady    string
	DockerHoldRelease  string
	DockerHoldService  string
	DockerHoldSocket   string
	ControlSocket      string
	StatusSocket       string
}

func DefaultPaths() Paths {
	return Paths{
		Config: "/etc/nftfw/nftfw.toml", Intent: "/etc/nftfw/intent.toml",
		VPN: intent.VPNConfig, Sysctl: "/etc/sysctl.d/90-nftfw-managed.conf",
		StateDir: "/var/lib/nftfw", RuntimeDir: "/run/nftfw",
		SystemdDir:         "/etc/systemd/system",
		DockerDaemon:       "/etc/docker/daemon.json",
		DockerDropIn:       "/etc/systemd/system/nftfwd.service.d/docker-access.conf",
		InitramfsMarker:    "/etc/nftfw/initramfs-managed-disabled-v1",
		InitramfsOwner:     "/etc/nftfw/initramfs-source-owner-v1",
		InitramfsLoader:    "/etc/initramfs-tools/scripts/init-top/nftfw-ipv6-early",
		InitramfsGate:      "/etc/initramfs-tools/scripts/init-top/udev",
		InitramfsManager:   "/usr/lib/nftfw/initramfs/nftfw-initramfs-manage",
		GRUBFragment:       "/etc/default/grub.d/90-nftfw-ipv6-disabled.cfg",
		GRUBSourceDir:      "/etc/default/grub.d",
		GRUBGenerated:      "/boot/grub/grub.cfg",
		GRUBUpdate:         "/usr/sbin/update-grub",
		BootKernelDir:      "/boot",
		ProcCmdline:        "/proc/cmdline",
		ProcBootID:         "/proc/sys/kernel/random/boot_id",
		IPv6DisableParam:   "/sys/module/ipv6/parameters/disable",
		ProcIfInet6:        "/proc/net/if_inet6",
		SystemdBootEntries: "/boot/loader/entries",
		UKIDir:             "/boot/EFI/Linux",
		ExtlinuxDir:        "/boot/extlinux",
		AlternateGRUBDir:   "/boot/grub2",
		EFIFirmwareDir:     "/sys/firmware/efi",
		EFIBootManager:     "/usr/bin/efibootmgr",
		BootHoldMarker:     "/etc/nftfw/setup-boot-hold-v1",
		BootHoldReady:      "/run/nftfw/setup-boot-hold-ready",
		BootHoldRelease:    "/run/nftfw/setup-boot-release",
		DockerHoldReady:    "/run/nftfw/setup-docker-hold-ready",
		DockerHoldRelease:  "/run/nftfw/setup-docker-release",
		DockerHoldService:  "/run/systemd/generator/docker.service.d/50-nftfw-setup-hold.conf",
		DockerHoldSocket:   "/run/systemd/generator/docker.socket.d/50-nftfw-setup-hold.conf",
		ControlSocket:      "/run/nftfw/control.sock", StatusSocket: "/run/nftfw/status.sock",
	}
}

type System struct {
	Paths                Paths
	Runner               routing.Runner
	Discover             func(context.Context) (discovery.Snapshot, error)
	ReadProfile          func(string) (wgconfig.Profile, wgconfig.Summary, error)
	Resolve              func(context.Context, string) ([]netip.Addr, error)
	Resolver             func(context.Context, routing.Runner, bool) (routing.ResolverMode, error)
	Control              func(context.Context, api.Request) (any, error)
	Status               func(context.Context) (health.Snapshot, error)
	ValidateHook         func(context.Context, prepared, uint64) error
	Connectivity         func(context.Context) error
	DNSLookup            func(context.Context, string) ([]string, error)
	ConfirmDockerRestart func(Summary) error
	ValidationTimeout    time.Duration
	ValidationPoll       time.Duration
	RuntimeReady         func(context.Context) error
	RuntimeReadyTimeout  time.Duration
	RuntimeReadyPoll     time.Duration
	Now                  func() time.Time
	InspectBoot          func(context.Context) (*bootObservation, error)
	runtimeProcessRoot   string
	runtimeProcessUID    *uint32
}

var errRuntimeStarting = errors.New("SETUP_DAEMON_STARTING")

type prepared struct {
	Profile       wgconfig.Profile
	Intent        intent.Intent
	Config        config.Config
	IntentData    []byte
	ConfigData    []byte
	VPNData       []byte
	GuardData     []byte
	SysctlData    []byte
	DockerData    []byte
	DockerChanged bool
	PolicyData    []byte
	Route         routing.Config
	BackupDir     string
	Boot          *bootObservation
	Resume        *Journal
}

func preparedResumeEndpoints(private *prepared) ([]netip.Addr, error) {
	if private == nil {
		return nil, errors.New("SETUP_PREPARED_IDENTITY_FAILED")
	}
	result := make([]netip.Addr, len(private.Intent.BootstrapIPv4))
	for index, raw := range private.Intent.BootstrapIPv4 {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || prefix.Bits() != 32 || !prefix.Addr().Is4() {
			return nil, errors.New("SETUP_PREPARED_IDENTITY_FAILED")
		}
		result[index] = prefix.Addr()
	}
	values := make([]string, len(result))
	for index, address := range result {
		values[index] = address.String()
	}
	if !validResumeEndpoints(values) {
		return nil, errors.New("SETUP_PREPARED_IDENTITY_FAILED")
	}
	return result, nil
}

func (s *System) Prepare(ctx context.Context, vpnPath string) (Plan, error) {
	s.defaults()
	readProfile := s.ReadProfile
	if readProfile == nil {
		readProfile = wgconfig.Read
	}
	profile, profileSummary, err := readProfile(vpnPath)
	if err != nil {
		return Plan{}, errors.New(wgconfig.RedactedError(err))
	}
	journalPath := filepath.Join(s.Paths.StateDir, "setup", "journal.json")
	var retainedResume *Journal
	var retainedDocker *discovery.DockerState
	if current, _, _, journalErr := readJournalFile(journalPath); journalErr == nil &&
		rebootRequiredJournal(current) {
		manifest, manifestErr := readBackup(current.BackupDir)
		if manifestErr != nil || manifest.Boot == nil || !validBootBackup(*manifest.Boot) {
			return Plan{}, errors.New("SETUP_RESUME_STATE_INVALID")
		}
		retainedResume = &current
		retainedDocker = &discovery.DockerState{
			Present: manifest.Boot.ResumeDockerPresent,
			Clean:   manifest.Boot.ResumeDockerClean,
			Networks: append([]config.DockerNetwork(nil),
				manifest.Boot.ResumeDockerNetworks...),
		}
	}
	discover := s.Discover
	if discover == nil {
		inspector := discovery.Inspector{Runner: discoveryAdapter{s.Runner}}
		if retainedDocker == nil {
			discover = inspector.Inspect
		} else {
			docker := *retainedDocker
			discover = func(ctx context.Context) (discovery.Snapshot, error) {
				return inspector.InspectWithDockerState(ctx, docker)
			}
		}
	}
	snapshot, err := discover(ctx)
	if err != nil {
		return Plan{}, err
	}
	var retired *retiredFirstSetup
	var resume *Journal
	if snapshot.ExistingNFTFWState {
		if retainedResume != nil {
			resume = retainedResume
			snapshot.ExistingNFTFWState = false
		} else {
			classified, classificationErr := inspectRetiredFirstSetup(ctx, s.Runner, s.Paths, snapshot)
			if classificationErr != nil {
				return Plan{}, retiredSetupRefusal(classificationErr)
			}
			retired = &classified
			snapshot.ExistingNFTFWState = false
		}
	} else if retainedResume != nil {
		return Plan{}, errors.New("SETUP_RESUME_STATE_INVALID")
	}
	cleanSnapshot := snapshot
	cleanSnapshot.ExistingNFTFWState = false
	if resume != nil && (snapshot.ForeignNFTables || snapshot.OwnedNFTables ||
		runtimeStatePresent(s.Paths.BootHoldReady)) {
		if err := s.verifyResumeNetworkState(ctx, *resume); err != nil {
			return Plan{}, err
		}
		cleanSnapshot.ForeignNFTables = false
		cleanSnapshot.OwnedNFTables = false
		snapshot.ForeignNFTables = false
		snapshot.OwnedNFTables = false
	}
	if err := cleanSnapshot.ValidateCleanHost(); err != nil {
		return Plan{}, err
	}
	resolve := s.Resolve
	if resolve == nil {
		resolve = resolveIPv4
	}
	var endpoints []netip.Addr
	if resume != nil {
		if err := validateRetiredBackupPath(s.Paths.StateDir, resume.BackupDir); err != nil {
			return Plan{}, errors.New("SETUP_RESUME_STATE_INVALID")
		}
		manifest, manifestErr := readBackup(resume.BackupDir)
		if manifestErr != nil || manifest.Boot == nil {
			return Plan{}, errors.New("SETUP_RESUME_STATE_INVALID")
		}
		endpoints, err = resumeEndpointAddresses(*manifest.Boot)
	} else {
		endpoints, err = resolve(ctx, profile.Peer.EndpointHost)
	}
	if err != nil {
		if resume != nil {
			return Plan{}, errors.New("SETUP_RESUME_STATE_INVALID")
		}
		return Plan{}, errors.New("SETUP_ENDPOINT_RESOLUTION_FAILED")
	}
	managedIntent, err := intent.New(snapshot, profile, endpoints)
	if err != nil {
		return Plan{}, err
	}
	managedConfig, err := managedIntent.Config()
	if err != nil {
		return Plan{}, errors.New("SETUP_CONFIG_GENERATION_FAILED")
	}
	configData, err := intent.RenderConfig(managedConfig)
	if err != nil {
		return Plan{}, err
	}
	effective, err := policy.Compile(managedConfig)
	if err != nil {
		return Plan{}, errors.New("SETUP_POLICY_COMPILATION_FAILED")
	}
	var dockerIPv4 []string
	for _, network := range managedConfig.DockerNetworks {
		dockerIPv4 = append(dockerIPv4, network.Subnets...)
	}
	artifact, err := compiler.Compile(compiler.Input{
		Policy: effective, BootstrapV4: managedConfig.WireGuard.BootstrapIPs,
		DockerNets: dockerIPv4,
	}, 0)
	if err != nil {
		return Plan{}, errors.New("SETUP_POLICY_COMPILATION_FAILED")
	}
	if retired != nil && retired.LatestGeneration != 0 &&
		!sameProvenanceIdentity(retired.Provenance, artifact.Provenance) {
		return Plan{}, errors.New("DISCOVERY_EXISTING_NFTFW_REQUIRES_ADOPT")
	}
	vpnData, err := profile.NormalizedWGQuick(intent.VPNInterface)
	if err != nil {
		return Plan{}, err
	}
	resolverDetector := s.Resolver
	if resolverDetector == nil {
		resolverDetector = routing.DetectResolver
	}
	resolverMode, err := resolverDetector(ctx, s.Runner, len(profile.DNS) > 0)
	if err != nil {
		return Plan{}, err
	}
	managedIntent.ResolverMode = string(resolverMode)
	intentData, err := managedIntent.Render()
	if err != nil {
		return Plan{}, err
	}
	guardData, err := renderGuard(
		snapshot.Uplink, intent.VPNInterface, intent.VPNFwmark,
		int(profile.Peer.EndpointPort), managedIntent.BootstrapIPv4,
		managedIntent.LANNetworks, managedIntent.ManagementTCP,
	)
	if err != nil {
		return Plan{}, err
	}
	routeConfig := routing.Config{
		Interface: intent.VPNInterface, Uplink: snapshot.Uplink,
		Fwmark: intent.VPNFwmark, Table: routing.DefaultTable,
		Addresses: profile.Addresses, EndpointAddress: endpoints[0],
		DNS: profile.DNS, MTU: profile.MTU, Profile: profile,
		Resolver: resolverMode, RuntimeDir: filepath.Join(s.Paths.RuntimeDir, "setup"),
	}
	if err := routeConfig.Validate(); err != nil {
		return Plan{}, err
	}
	if err := (routing.Manager{Runner: s.Runner}).PreflightClean(ctx, routeConfig); err != nil {
		return Plan{}, err
	}
	ipv6Interfaces := append([]string(nil), snapshot.NonLoopbackInterfaces...)
	if len(ipv6Interfaces) == 0 {
		ipv6Interfaces = []string{snapshot.Uplink}
	}
	sort.Strings(ipv6Interfaces)
	var dockerData []byte
	dockerChanged := false
	if managedIntent.DockerEnabled {
		dockerData, dockerChanged, err = containers.ManagedDaemonConfig(s.Paths.DockerDaemon)
		if err != nil {
			return Plan{}, err
		}
	}
	private := &prepared{
		Profile: profile, Intent: managedIntent, Config: managedConfig,
		IntentData: intentData, ConfigData: configData, VPNData: vpnData,
		GuardData:  guardData,
		DockerData: dockerData, DockerChanged: dockerChanged,
		PolicyData: []byte(artifact.Script), Route: routeConfig,
	}
	inspectBoot := s.InspectBoot
	if inspectBoot == nil {
		inspectBoot = func(ctx context.Context) (*bootObservation, error) {
			observation, err := inspectManagedGRUB(ctx, s.Runner, s.Paths, resume != nil)
			return &observation, err
		}
	}
	boot, err := inspectBoot(ctx)
	if err != nil {
		return Plan{}, err
	}
	private.Boot = boot
	private.SysctlData = renderSysctl(ipv6Interfaces, managedIntent.DockerEnabled, boot != nil)
	dockerMode := "disabled"
	var dockerNames []string
	if managedIntent.DockerEnabled {
		dockerMode = "enabled"
		for _, network := range managedIntent.DockerNetworks {
			dockerNames = append(dockerNames, network.Name)
		}
	}
	plan := Plan{
		VPNSource: vpnPath,
		Summary: Summary{
			Schema: "nftfw.setup-plan.v1", Uplink: snapshot.Uplink,
			VPNInterface: intent.VPNInterface, IPv6Interfaces: ipv6Interfaces,
			LANNetworks:   managedIntent.LANNetworks,
			ManagementTCP: managedIntent.ManagementTCP,
			PublicTCP:     managedIntent.PublicTCP, PublicUDP: managedIntent.PublicUDP,
			IPv6Mode: "disabled", DockerMode: dockerMode,
			DockerNetworks: dockerNames, DockerRestart: dockerChanged,
			ResolverMode: string(resolverMode), SourceModeWarning: profileSummary.SourceWorldReadable,
		},
		PrivateData: private,
	}
	if boot != nil {
		plan.Summary.BootPolicy = ManagedBootPolicy
	}
	if resume != nil {
		if boot == nil || !boot.Prepared || !reflect.DeepEqual(resume.Summary, plan.Summary) {
			return Plan{}, errors.New("SETUP_RESUME_STATE_INVALID")
		}
		if err := validateRetiredBackupPath(s.Paths.StateDir, resume.BackupDir); err != nil {
			return Plan{}, errors.New("SETUP_RESUME_STATE_INVALID")
		}
		manifest, manifestErr := readBackup(resume.BackupDir)
		identity, identityErr := preparedPlanSHA256(plan, private)
		resumeGuard, resumeGuardErr := renderResumeGuard(private.GuardData)
		storedGuard, storedGuardErr := readResumeGuard(resume.BackupDir, manifest)
		if manifestErr != nil || identityErr != nil || manifest.PreparedSHA256 != identity ||
			manifest.Boot == nil || !validBootBackup(*manifest.Boot) ||
			!verifyPreparedBoot(*boot, *manifest.Boot) || resumeGuardErr != nil ||
			storedGuardErr != nil || !bytes.Equal(resumeGuard, storedGuard) {
			return Plan{}, errors.New("SETUP_RESUME_STATE_INVALID")
		}
		private.BackupDir, private.Resume = resume.BackupDir, resume
		plan.ResumeJournal = resume
		if boot.BootID != manifest.Boot.PreBootID {
			if err := verifyRunningBoot(s.Paths, manifest.Boot.PreBootID); err != nil {
				return Plan{}, err
			}
			plan.ResumeReady = true
		}
	}
	if retired != nil {
		if !reflect.DeepEqual(retired.Summary, plan.Summary) {
			return Plan{}, errors.New("DISCOVERY_EXISTING_NFTFW_REQUIRES_ADOPT")
		}
		plan.PriorJournalSHA256 = retired.PriorJournalSHA256
	}
	return plan, nil
}

func (s *System) Backup(ctx context.Context, plan Plan) (string, error) {
	s.defaults()
	private, err := privatePlan(plan)
	if err != nil {
		return "", err
	}
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	directory := filepath.Join(s.Paths.StateDir, "setup", "backups", now().UTC().Format("20060102T150405.000000000Z"))
	units, err := s.managedUnitsForBackup(ctx, plan.Summary.DockerMode == "enabled")
	if err != nil {
		return "", err
	}
	manifest, err := createBackup(
		ctx, s.Runner, directory, s.touchedFiles(plan), units,
		managedSysctls(plan.Summary.IPv6Interfaces, plan.Summary.DockerMode == "enabled"),
	)
	if err != nil {
		return "", err
	}
	if manifest.Path == "" {
		return "", errors.New("SETUP_BACKUP_INVALID")
	}
	if private.Boot != nil {
		identity, err := preparedPlanSHA256(plan, private)
		if err != nil {
			return "", err
		}
		endpoints, err := preparedResumeEndpoints(private)
		if err != nil {
			return "", err
		}
		manifest.PreparedSHA256, manifest.Boot = identity,
			private.Boot.backup(endpoints, private.Intent.DockerNetworks)
		if err := writeBackupManifest(manifest); err != nil {
			return "", err
		}
	}
	private.BackupDir = directory
	return directory, nil
}

func (s *System) BootTransactionRequired(plan Plan) bool {
	private, err := privatePlan(plan)
	return err == nil && private.Boot != nil && plan.Summary.BootPolicy == ManagedBootPolicy
}

func (s *System) PrepareBoot(ctx context.Context, plan Plan) error {
	s.defaults()
	private, err := privatePlan(plan)
	if err != nil || private.Boot == nil || private.Resume != nil || private.BackupDir == "" {
		return errors.New("SETUP_BOOT_PREPARE_STATE_INVALID")
	}
	manifest, err := readBackup(private.BackupDir)
	identity, identityErr := preparedPlanSHA256(plan, private)
	if err != nil || identityErr != nil || manifest.PreparedSHA256 != identity || manifest.Boot == nil ||
		!sameInitialBoot(*private.Boot, *manifest.Boot) {
		return errors.New("SETUP_BOOT_PREPARE_STATE_INVALID")
	}
	resumeGuard, err := renderResumeGuard(private.GuardData)
	if err != nil {
		return err
	}
	resumeGuardSHA, err := publishResumeGuard(private.BackupDir, resumeGuard)
	if err != nil {
		return err
	}
	manifest.Boot.ResumeGuardSHA256 = resumeGuardSHA
	if err := writeBackupManifest(manifest); err != nil {
		return err
	}
	current, err := inspectManagedGRUB(ctx, s.Runner, s.Paths, false)
	if err != nil || !sameInitialBoot(current, *manifest.Boot) {
		return errors.New("SETUP_BOOT_STATE_CHANGED")
	}
	if _, err := s.Runner.Run(ctx, nil, "systemctl", "enable", "--now", "nftfw-setup-rollback.timer"); err != nil {
		return errors.New("SETUP_WATCHDOG_START_FAILED")
	}
	if _, err := s.Runner.Run(ctx, nil, s.Paths.InitramfsManager, "rebuild-enabled"); err != nil {
		return errors.New("SETUP_INITRAMFS_GUARD_FAILED")
	}
	if err := publishBootHoldMarker(s.Paths.BootHoldMarker); err != nil {
		return err
	}
	if err := publishGRUBFragment(s.Paths.GRUBFragment); err != nil {
		return err
	}
	if err := runGRUBUpdate(ctx, s.Runner, s.Paths.GRUBUpdate); err != nil {
		return err
	}
	preparedBoot, err := inspectManagedGRUB(ctx, s.Runner, s.Paths, true)
	if err != nil || preparedBoot.BootID != manifest.Boot.PreBootID ||
		preparedBoot.MountSHA256 != manifest.Boot.MountSHA256 ||
		preparedBoot.KernelSHA256 != manifest.Boot.KernelSHA256 {
		return errors.New("SETUP_BOOT_PREPARE_VERIFY_FAILED")
	}
	manifest.Boot.PreparedGeneratedSHA256 = preparedBoot.GeneratedSHA256
	fragmentSum := sha256.Sum256([]byte(grubFragmentData))
	manifest.Boot.FragmentSHA256 = fmt.Sprintf("%x", fragmentSum[:])
	if err := writeBackupManifest(manifest); err != nil {
		return err
	}
	private.Boot = &preparedBoot
	return nil
}

func (s *System) VerifyBootResume(ctx context.Context, plan Plan) error {
	s.defaults()
	private, err := privatePlan(plan)
	if err != nil || private.Resume == nil || private.BackupDir == "" || !plan.ResumeReady {
		return errors.New("SETUP_RESUME_STATE_INVALID")
	}
	manifest, err := readBackup(private.BackupDir)
	if err != nil || manifest.Boot == nil {
		return errors.New("SETUP_RESUME_STATE_INVALID")
	}
	observation, err := inspectManagedGRUB(ctx, s.Runner, s.Paths, true)
	if err != nil || !verifyPreparedBoot(observation, *manifest.Boot) ||
		verifyRunningBoot(s.Paths, manifest.Boot.PreBootID) != nil {
		return errors.New("SETUP_RESUME_STATE_INVALID")
	}
	if _, err := s.Runner.Run(ctx, nil, s.Paths.InitramfsManager, "verify-enabled"); err != nil {
		return errors.New("SETUP_INITRAMFS_GUARD_FAILED")
	}
	return nil
}

func (s *System) PendingBootStatus(ctx context.Context, journal Journal) (string, error) {
	s.defaults()
	if !rebootRequiredJournal(journal) || journal.Summary.BootPolicy != ManagedBootPolicy ||
		validateRetiredBackupPath(s.Paths.StateDir, journal.BackupDir) != nil {
		return "", errors.New("SETUP_BOOT_STATUS_INVALID")
	}
	manifest, err := readBackup(journal.BackupDir)
	if err != nil || manifest.Boot == nil || !validBootBackup(*manifest.Boot) {
		return "", errors.New("SETUP_BOOT_STATUS_INVALID")
	}
	observation, err := inspectManagedGRUBRuntime(ctx, s.Runner, s.Paths)
	if err != nil {
		return "", errors.New(errorCode(err))
	}
	if !verifyPreparedBoot(observation, *manifest.Boot) {
		return "", errors.New("SETUP_BOOT_PREPARED_IDENTITY_INVALID")
	}
	if observation.BootID == manifest.Boot.PreBootID {
		return "reboot_required", nil
	}
	if err := verifyRunningBoot(s.Paths, manifest.Boot.PreBootID); err != nil {
		return "", errors.New(errorCode(err))
	}
	if _, err := s.Runner.Run(ctx, nil, s.Paths.InitramfsManager, "verify-enabled"); err != nil {
		return "", errors.New("SETUP_INITRAMFS_GUARD_FAILED")
	}
	return "resume_ready", nil
}

func (s *System) FinalizeBootRollback(ctx context.Context, journal Journal) error {
	s.defaults()
	if journal.Status != "rollback_reboot_required" || journal.Phase != PhaseFailed ||
		journal.Summary.BootPolicy != ManagedBootPolicy ||
		validateRetiredBackupPath(s.Paths.StateDir, journal.BackupDir) != nil {
		return errors.New("SETUP_ROLLBACK_REBOOT_STATE_INVALID")
	}
	if runningKernelHasManagedDisable(s.Paths) {
		return errors.New("SETUP_ROLLBACK_REBOOT_STILL_REQUIRED")
	}
	manifest, err := verifyRestoredBackupDeferring(
		ctx, s.Runner, journal.BackupDir, anyBackupSysctl,
	)
	if err != nil || manifest.Boot == nil {
		return errors.New("SETUP_ROLLBACK_REBOOT_STATE_INVALID")
	}
	observation, err := inspectManagedGRUB(ctx, s.Runner, s.Paths, false)
	if err != nil || observation.Prepared || observation.MountSHA256 != manifest.Boot.MountSHA256 ||
		observation.KernelSHA256 != manifest.Boot.KernelSHA256 ||
		observation.GeneratedSHA256 != manifest.Boot.InitialGeneratedSHA256 {
		return errors.New("SETUP_ROLLBACK_REBOOT_STATE_INVALID")
	}
	if _, err := s.Runner.Run(ctx, nil, s.Paths.InitramfsManager, "verify-disabled"); err != nil {
		return errors.New("SETUP_ROLLBACK_REBOOT_STATE_INVALID")
	}
	// A reboot can reset every volatile sysctl, including IPv4 forwarding that
	// was successfully restored before the reboot. Reapply the complete saved
	// set only after the static boot/files/unit identity is verified, then prove
	// the full backup again before terminalizing recovery.
	if err := restoreDeferredSysctls(ctx, s.Runner, journal.BackupDir, anyBackupSysctl); err != nil {
		return errors.New("SETUP_ROLLBACK_RESTORE_SYSCTL_FAILED")
	}
	if _, err := verifyRestoredBackup(ctx, s.Runner, journal.BackupDir); err != nil {
		return errors.New("SETUP_ROLLBACK_REBOOT_STATE_INVALID")
	}
	return nil
}

// HandoffBootPolicy removes only the managed pre-driver boot ownership during
// package removal or an exact downgrade. It deliberately leaves firewall,
// VPN, Docker, and ordinary managed configuration to their separate lifecycle.
func (s *System) HandoffBootPolicy(ctx context.Context, journal Journal) (bool, error) {
	s.defaults()
	if journal.Summary.BootPolicy != ManagedBootPolicy || journal.BackupDir == "" ||
		validateRetiredBackupPath(s.Paths.StateDir, journal.BackupDir) != nil {
		return false, errors.New("SETUP_BOOT_HANDOFF_STATE_INVALID")
	}
	manifest, err := readBackup(journal.BackupDir)
	if err != nil || manifest.Boot == nil || !validBootBackup(*manifest.Boot) ||
		manifest.Boot.PreparedGeneratedSHA256 == "" {
		return false, errors.New("SETUP_BOOT_HANDOFF_STATE_INVALID")
	}
	if journal.Status == "rollback_reboot_required" {
		restored, inspectErr := inspectManagedGRUB(ctx, s.Runner, s.Paths, false)
		if inspectErr != nil || restored.Prepared || restored.MountSHA256 != manifest.Boot.MountSHA256 ||
			restored.KernelSHA256 != manifest.Boot.KernelSHA256 ||
			restored.GeneratedSHA256 != manifest.Boot.InitialGeneratedSHA256 {
			return false, errors.New("SETUP_BOOT_HANDOFF_STATE_INVALID")
		}
		if _, verifyErr := s.Runner.Run(ctx, nil, s.Paths.InitramfsManager, "verify-disabled"); verifyErr != nil {
			return false, errors.New("SETUP_BOOT_HANDOFF_STATE_INVALID")
		}
		if removeErr := s.removeResumeGuard(ctx); removeErr != nil {
			return false, removeErr
		}
		if releaseErr := s.releaseDockerHold(); releaseErr != nil {
			return false, releaseErr
		}
		if cleanupErr := s.cleanupDockerHold(ctx); cleanupErr != nil {
			return false, cleanupErr
		}
		if releaseErr := s.releaseBootHold(ctx); releaseErr != nil {
			return false, releaseErr
		}
		return runningKernelHasManagedDisable(s.Paths), nil
	}
	observation, err := inspectManagedGRUBState(
		ctx, s.Runner, s.Paths, true, journal.Status != "complete", true,
	)
	if err != nil || !verifyPreparedBoot(observation, *manifest.Boot) {
		return false, errors.New("SETUP_BOOT_HANDOFF_STATE_INVALID")
	}
	if _, err := s.Runner.Run(ctx, nil, s.Paths.InitramfsManager, "disable"); err != nil {
		return false, errors.New("SETUP_BOOT_HANDOFF_INITRAMFS_FAILED")
	}
	if err := restoreBackupFiles(journal.BackupDir, []string{
		s.Paths.InitramfsMarker, s.Paths.InitramfsOwner, s.Paths.InitramfsLoader,
		s.Paths.InitramfsGate, s.Paths.GRUBFragment, s.Paths.GRUBGenerated,
		s.Paths.BootHoldMarker,
	}); err != nil {
		return false, err
	}
	restored, err := inspectManagedGRUB(ctx, s.Runner, s.Paths, false)
	if err != nil || restored.Prepared || restored.MountSHA256 != manifest.Boot.MountSHA256 ||
		restored.KernelSHA256 != manifest.Boot.KernelSHA256 ||
		restored.GeneratedSHA256 != manifest.Boot.InitialGeneratedSHA256 {
		return false, errors.New("SETUP_BOOT_HANDOFF_VERIFY_FAILED")
	}
	if _, err := s.Runner.Run(ctx, nil, s.Paths.InitramfsManager, "verify-disabled"); err != nil {
		return false, errors.New("SETUP_BOOT_HANDOFF_VERIFY_FAILED")
	}
	if err := s.removeResumeGuard(ctx); err != nil {
		return false, err
	}
	if err := s.releaseDockerHold(); err != nil {
		return false, err
	}
	if err := s.cleanupDockerHold(ctx); err != nil {
		return false, err
	}
	if err := s.releaseBootHold(ctx); err != nil {
		return false, err
	}
	return runningKernelHasManagedDisable(s.Paths), nil
}

func (s *System) releaseBootHold(ctx context.Context) error {
	s.defaults()
	_ = ctx
	for _, state := range []struct {
		path string
		data string
	}{
		{path: s.Paths.BootHoldReady, data: bootHoldReadyData},
		{path: s.Paths.BootHoldRelease, data: bootHoldReleaseData},
	} {
		present, err := protectedFixedRuntimeState(state.path, state.data)
		if err != nil {
			return errors.New("SETUP_BOOT_HOLD_STATE_INVALID")
		}
		if present && (os.Remove(state.path) != nil ||
			syncSetupDirectory(filepath.Dir(state.path)) != nil) {
			return errors.New("SETUP_BOOT_HOLD_RELEASE_CLEANUP_FAILED")
		}
	}
	return nil
}

// WaitBootHold is invoked only by the transient boot dependency emitted by
// the packaged generator. The CLI owns the setup lock while this method
// atomically replaces the initramfs deny guard with the checksum-bound resume
// guard. Returning releases network-pre only after that protected boundary.
func (s *System) WaitBootHold(ctx context.Context, store JournalStore) error {
	s.defaults()
	ready, err := protectedFixedRuntimeState(s.Paths.BootHoldReady, bootHoldReadyData)
	if err != nil {
		return errors.New("SETUP_BOOT_HOLD_STATE_INVALID")
	}
	if ready {
		journal, readErr := store.Read()
		if readErr != nil || s.verifyResumeNetworkState(ctx, journal) != nil {
			return errors.New("SETUP_BOOT_HOLD_STATE_INVALID")
		}
		return nil
	}
	lastErrorCode := ""
	for {
		journal, readErr := store.Read()
		status := ""
		if readErr == nil && rebootRequiredJournal(journal) && journal.Summary.BootPolicy == ManagedBootPolicy {
			status, readErr = s.PendingBootStatus(ctx, journal)
		}
		if readErr == nil && status == "resume_ready" {
			if err := s.activateResumeGuard(ctx, journal); err != nil {
				return err
			}
			if err := publishFixedRuntimeFile(s.Paths.BootHoldReady, []byte(bootHoldReadyData)); err != nil {
				return err
			}
			return nil
		}
		if readErr != nil {
			code := errorCode(readErr)
			if code != lastErrorCode {
				// Only the fixed uppercase error code reaches the boot journal;
				// paths, command lines, profile data, and administrator arguments
				// remain private while local recovery gains an actionable reason.
				fmt.Fprintf(os.Stderr, "NFTFW boot hold waiting: %s\n", code)
				lastErrorCode = code
			}
		}
		select {
		case <-ctx.Done():
			return errors.New("SETUP_BOOT_HOLD_CANCELED")
		case <-time.After(time.Second):
		}
	}
}

func (s *System) activateResumeGuard(ctx context.Context, journal Journal) error {
	if !rebootRequiredJournal(journal) || validateRetiredBackupPath(s.Paths.StateDir, journal.BackupDir) != nil {
		return errors.New("SETUP_RESUME_GUARD_STATE_INVALID")
	}
	manifest, err := readBackup(journal.BackupDir)
	if err != nil || manifest.Boot == nil || !validBootBackup(*manifest.Boot) {
		return errors.New("SETUP_RESUME_GUARD_STATE_INVALID")
	}
	guard, err := readResumeGuard(journal.BackupDir, manifest)
	if err != nil {
		return err
	}
	initramfsPresent, initramfsErr := bootguard.Verify(ctx, setupBootGuardRunner{s.Runner})
	resumePresent := s.resumeGuardPresent(ctx)
	switch {
	case initramfsErr == nil && initramfsPresent && !resumePresent:
		if err := s.requireExactNFTTables(ctx, "inet/"+bootguard.TableName); err != nil {
			return err
		}
		path := filepath.Join(s.Paths.RuntimeDir, "setup-resume-guard.nft")
		batch := append([]byte("delete table inet "+bootguard.TableName+"\n"), guard...)
		if err := writeAtomic(path, batch, 0o600); err != nil {
			return err
		}
		defer os.Remove(path)
		if _, err := s.Runner.Run(ctx, nil, "nft", "--check", "--file", path); err != nil {
			return errors.New("SETUP_RESUME_GUARD_CHECK_FAILED")
		}
		if _, err := s.Runner.Run(ctx, nil, "nft", "--file", path); err != nil {
			return errors.New("SETUP_RESUME_GUARD_APPLY_FAILED")
		}
	case initramfsErr == nil && !initramfsPresent && resumePresent:
		// A prior process completed the atomic nft transaction and died before
		// publishing the runtime readiness marker. Revalidate and continue.
	default:
		return errors.New("SETUP_RESUME_GUARD_STATE_INVALID")
	}
	if err := s.requireExactNFTTables(ctx, "inet/"+resumeGuardTable); err != nil {
		return err
	}
	return nil
}

func (s *System) verifyResumeNetworkState(ctx context.Context, journal Journal) error {
	ready, err := protectedFixedRuntimeState(s.Paths.BootHoldReady, bootHoldReadyData)
	if err != nil || !ready || !rebootRequiredJournal(journal) ||
		validateRetiredBackupPath(s.Paths.StateDir, journal.BackupDir) != nil {
		return errors.New("SETUP_RESUME_GUARD_STATE_INVALID")
	}
	manifest, err := readBackup(journal.BackupDir)
	if err != nil {
		return errors.New("SETUP_RESUME_GUARD_STATE_INVALID")
	}
	if _, err := readResumeGuard(journal.BackupDir, manifest); err != nil {
		return err
	}
	initramfsPresent, err := bootguard.Verify(ctx, setupBootGuardRunner{s.Runner})
	if err != nil || initramfsPresent || !s.resumeGuardPresent(ctx) {
		return errors.New("SETUP_RESUME_GUARD_STATE_INVALID")
	}
	return s.requireExactNFTTables(ctx, "inet/"+resumeGuardTable)
}

func (s *System) resumeGuardPresent(ctx context.Context) bool {
	_, err := s.Runner.Run(ctx, nil, "nft", "list", "table", "inet", resumeGuardTable)
	return err == nil
}

func (s *System) removeResumeGuard(ctx context.Context) error {
	if !s.resumeGuardPresent(ctx) {
		return nil
	}
	if _, err := s.Runner.Run(ctx, nil, "nft", "delete", "table", "inet", resumeGuardTable); err != nil ||
		s.resumeGuardPresent(ctx) {
		return errors.New("SETUP_RESUME_GUARD_REMOVE_FAILED")
	}
	return nil
}

func (s *System) requireExactNFTTables(ctx context.Context, names ...string) error {
	output, err := s.Runner.Run(ctx, nil, "nft", "--json", "list", "ruleset")
	if err != nil || len(output) == 0 || len(output) > 1<<20 {
		return errors.New("SETUP_RESUME_GUARD_VERIFY_FAILED")
	}
	var document struct {
		Objects []map[string]json.RawMessage `json:"nftables"`
	}
	if json.Unmarshal(output, &document) != nil {
		return errors.New("SETUP_RESUME_GUARD_VERIFY_FAILED")
	}
	want := make(map[string]bool, len(names))
	for _, name := range names {
		if name == "" || want[name] {
			return errors.New("SETUP_RESUME_GUARD_VERIFY_FAILED")
		}
		want[name] = true
	}
	seen := map[string]bool{}
	for _, object := range document.Objects {
		raw, ok := object["table"]
		if !ok {
			continue
		}
		var table struct {
			Family string `json:"family"`
			Name   string `json:"name"`
		}
		if json.Unmarshal(raw, &table) != nil || table.Family == "" || table.Name == "" {
			return errors.New("SETUP_RESUME_GUARD_VERIFY_FAILED")
		}
		identity := table.Family + "/" + table.Name
		if !want[identity] || seen[identity] {
			return errors.New("SETUP_RESUME_GUARD_VERIFY_FAILED")
		}
		seen[identity] = true
	}
	if !reflect.DeepEqual(want, seen) {
		return errors.New("SETUP_RESUME_GUARD_VERIFY_FAILED")
	}
	return nil
}

type setupBootGuardRunner struct{ runner routing.Runner }

func (r setupBootGuardRunner) Run(ctx context.Context, args ...string) (string, string, error) {
	output, err := r.runner.Run(ctx, nil, "nft", args...)
	return string(output), "", err
}

func runtimeStatePresent(path string) bool {
	_, err := os.Lstat(path)
	return err == nil || !errors.Is(err, os.ErrNotExist)
}

// WaitDockerHold is pulled only through transient generator drop-ins while a
// managed boot transaction marker exists. Docker remains queued until setup
// has durably published its daemon ownership files or exact rollback has
// restored the captured files.
func (s *System) WaitDockerHold(ctx context.Context) error {
	s.defaults()
	if err := verifyBootHoldMarker(s.Paths.BootHoldMarker, true); err != nil ||
		s.verifyDockerHoldFragments() != nil {
		return errors.New("SETUP_DOCKER_HOLD_STATE_INVALID")
	}
	if err := publishFixedRuntimeFile(s.Paths.DockerHoldReady, []byte(dockerHoldReadyData)); err != nil {
		return err
	}
	for {
		released, err := protectedFixedRuntimeState(s.Paths.DockerHoldRelease, dockerHoldReleaseData)
		if err != nil {
			return errors.New("SETUP_DOCKER_HOLD_STATE_INVALID")
		}
		if released {
			if err := os.Remove(s.Paths.DockerHoldReady); err != nil ||
				syncSetupDirectory(filepath.Dir(s.Paths.DockerHoldReady)) != nil {
				return errors.New("SETUP_DOCKER_HOLD_READY_CLEANUP_FAILED")
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.New("SETUP_DOCKER_HOLD_CANCELED")
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (s *System) verifyDockerHoldFragments() error {
	for _, fragment := range []struct {
		path string
		data string
	}{
		{path: s.Paths.DockerHoldService, data: dockerServiceHoldDropInData},
		{path: s.Paths.DockerHoldSocket, data: dockerSocketHoldDropInData},
	} {
		data, info, err := readBootRegular(fragment.path, 4<<10)
		if err != nil || info.Mode().Perm() != 0o644 || string(data) != fragment.data {
			return errors.New("SETUP_DOCKER_HOLD_STATE_INVALID")
		}
	}
	return nil
}

func (s *System) dockerHoldGenerated() (bool, error) {
	present := 0
	for _, path := range []string{s.Paths.DockerHoldService, s.Paths.DockerHoldSocket} {
		if _, err := os.Lstat(path); err == nil {
			present++
		} else if !errors.Is(err, os.ErrNotExist) {
			return false, errors.New("SETUP_DOCKER_HOLD_STATE_INVALID")
		}
	}
	if present == 0 {
		return false, nil
	}
	if present != 2 || s.verifyDockerHoldFragments() != nil {
		return false, errors.New("SETUP_DOCKER_HOLD_STATE_INVALID")
	}
	return true, nil
}

func (s *System) releaseDockerHold() error {
	s.defaults()
	generated, err := s.dockerHoldGenerated()
	if err != nil {
		return err
	}
	if !generated {
		return nil
	}
	return publishFixedRuntimeFile(s.Paths.DockerHoldRelease, []byte(dockerHoldReleaseData))
}

func (s *System) cleanupDockerHold(ctx context.Context) error {
	s.defaults()
	generated, err := s.dockerHoldGenerated()
	if err != nil {
		return err
	}
	ready, readyErr := protectedFixedRuntimeState(s.Paths.DockerHoldReady, dockerHoldReadyData)
	released, releaseErr := protectedFixedRuntimeState(s.Paths.DockerHoldRelease, dockerHoldReleaseData)
	if readyErr != nil || releaseErr != nil {
		return errors.New("SETUP_DOCKER_HOLD_STATE_INVALID")
	}
	if generated && !released {
		if err := s.releaseDockerHold(); err != nil {
			return err
		}
		released = true
	}
	if ready {
		deadline := time.Now().Add(30 * time.Second)
		for {
			if _, statErr := os.Lstat(s.Paths.DockerHoldReady); errors.Is(statErr, os.ErrNotExist) {
				break
			} else if statErr != nil {
				return errors.New("SETUP_DOCKER_HOLD_STATE_INVALID")
			}
			if !time.Now().Before(deadline) {
				return errors.New("SETUP_DOCKER_HOLD_RELEASE_TIMEOUT")
			}
			select {
			case <-ctx.Done():
				return errors.New("SETUP_DOCKER_HOLD_RELEASE_CANCELED")
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
	if released {
		if err := os.Remove(s.Paths.DockerHoldRelease); err != nil ||
			syncSetupDirectory(filepath.Dir(s.Paths.DockerHoldRelease)) != nil {
			return errors.New("SETUP_DOCKER_HOLD_RELEASE_CLEANUP_FAILED")
		}
	}
	return nil
}

func protectedFixedRuntimeState(path, expected string) (bool, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() != int64(len(expected)) {
		return false, errors.New("unsafe runtime state")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(stat.Uid) != int64(os.Geteuid()) || stat.Nlink != 1 {
		return false, errors.New("unsafe runtime state")
	}
	data, err := io.ReadAll(io.LimitReader(file, 4<<10))
	if err != nil || string(data) != expected {
		return false, errors.New("unsafe runtime state")
	}
	return true, nil
}

func publishFixedRuntimeFile(path string, data []byte) error {
	if exists, err := protectedFixedRuntimeState(path, string(data)); err != nil {
		return errors.New("SETUP_BOOT_HOLD_RELEASE_INVALID")
	} else if exists {
		return nil
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return errors.New("SETUP_BOOT_HOLD_RELEASE_FAILED")
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(data); err != nil || file.Sync() != nil || file.Close() != nil ||
		syncSetupDirectory(filepath.Dir(path)) != nil {
		return errors.New("SETUP_BOOT_HOLD_RELEASE_FAILED")
	}
	ok = true
	return nil
}

func (s *System) StartGuard(ctx context.Context, plan Plan) error {
	s.defaults()
	private, err := privatePlan(plan)
	if err != nil {
		return err
	}
	if _, err := s.Runner.Run(ctx, nil, "nft", "list", "table", "inet", "nftfw_setup_guard"); err == nil {
		return errors.New("SETUP_GUARD_ALREADY_EXISTS")
	}
	path := filepath.Join(s.Paths.RuntimeDir, "setup-guard.nft")
	if err := writeAtomic(path, private.GuardData, 0o600); err != nil {
		return err
	}
	if _, err := s.Runner.Run(ctx, nil, "nft", "--check", "--file", path); err != nil {
		return errors.New("SETUP_GUARD_CHECK_FAILED")
	}
	if _, err := s.Runner.Run(ctx, nil, "nft", "--file", path); err != nil {
		return errors.New("SETUP_GUARD_APPLY_FAILED")
	}
	if _, err := s.Runner.Run(ctx, nil, "systemctl", "enable", "--now", "nftfw-setup-rollback.timer"); err != nil {
		return errors.New("SETUP_WATCHDOG_START_FAILED")
	}
	return nil
}

func (s *System) Install(ctx context.Context, plan Plan) error {
	s.defaults()
	private, err := privatePlan(plan)
	if err != nil {
		return err
	}
	if private.Intent.DockerEnabled {
		if err := containers.ValidateManagedSocketDropInTarget(s.Paths.DockerDropIn); err != nil {
			return err
		}
	}
	candidatePath := filepath.Join(s.Paths.RuntimeDir, "setup-candidate.nft")
	if err := writeAtomic(candidatePath, private.PolicyData, 0o600); err != nil {
		return err
	}
	defer os.Remove(candidatePath)
	if _, err := s.Runner.Run(ctx, nil, "nft", "--check", "--file", candidatePath); err != nil {
		return errors.New("SETUP_POLICY_CHECK_FAILED")
	}
	if private.Intent.DockerEnabled {
		current, changed, err := containers.ManagedDaemonConfig(s.Paths.DockerDaemon)
		if err != nil || changed != private.DockerChanged ||
			!bytes.Equal(current, private.DockerData) {
			return errors.New("SETUP_DOCKER_CONFIG_CHANGED_AFTER_PLAN")
		}
		if plan.ResumeReady {
			generated, holdErr := s.dockerHoldGenerated()
			if holdErr != nil || !generated {
				return errors.New("SETUP_DOCKER_HOLD_STATE_INVALID")
			}
			if _, activeErr := s.Runner.Run(ctx, nil, "systemctl", "is-active", "--quiet", "docker.service"); activeErr == nil {
				return errors.New("SETUP_DOCKER_STARTED_BEFORE_OWNERSHIP")
			}
		} else {
			state, inspectErr := (discovery.Inspector{
				Runner: discoveryAdapter{s.Runner},
			}).InspectDocker(ctx)
			if inspectErr != nil || !state.Present || !state.Clean ||
				!sameDockerNetworks(state.Networks, private.Intent.DockerNetworks) {
				return errors.New("SETUP_DOCKER_STATE_CHANGED_AFTER_PLAN")
			}
		}
	}
	files := []struct {
		path string
		data []byte
		mode os.FileMode
	}{
		{s.Paths.VPN, private.VPNData, 0o600},
		{s.Paths.Intent, private.IntentData, 0o640},
		{s.Paths.Config, private.ConfigData, 0o640},
		{s.Paths.Sysctl, private.SysctlData, 0o644},
	}
	if private.Intent.DockerEnabled {
		files = append(files,
			struct {
				path string
				data []byte
				mode os.FileMode
			}{s.Paths.DockerDaemon, private.DockerData, 0o600},
			struct {
				path string
				data []byte
				mode os.FileMode
			}{s.Paths.DockerDropIn, []byte(containers.ManagedSocketDropIn), 0o644},
		)
	}
	for _, file := range files {
		if err := writeAtomic(file.path, file.data, file.mode); err != nil {
			return err
		}
	}
	settings := map[string]string{}
	if private.Intent.DockerEnabled {
		settings["net.ipv4.ip_forward"] = "1"
	}
	// ipv6.disable=1 removes /proc/sys/net/ipv6 on supported Debian kernels.
	// The verified boot boundary already owns the stronger pre-driver state, so
	// attempting the legacy runtime sysctls here would turn a valid resume into
	// a false failure. Keep them only for non-boot test/advanced executors.
	if plan.Summary.BootPolicy != ManagedBootPolicy {
		settings["net.ipv6.conf.default.disable_ipv6"] = "1"
		settings["net.ipv6.conf.all.forwarding"] = "0"
		settings["net.ipv6.conf.lo.disable_ipv6"] = "1"
		for _, name := range plan.Summary.IPv6Interfaces {
			settings["net.ipv6.conf."+name+".disable_ipv6"] = "1"
		}
	}
	settingKeys := make([]string, 0, len(settings))
	for key := range settings {
		settingKeys = append(settingKeys, key)
	}
	sort.Strings(settingKeys)
	for _, key := range settingKeys {
		value := settings[key]
		if _, err := s.Runner.Run(ctx, nil, "sysctl", "-w", key+"="+value); err != nil {
			return errors.New("SETUP_SYSCTL_APPLY_FAILED")
		}
	}
	if _, err := s.Runner.Run(ctx, nil, "systemctl", "daemon-reload"); err != nil {
		return errors.New("SETUP_SYSTEMD_RELOAD_FAILED")
	}
	if _, err := s.Runner.Run(ctx, nil, "systemd-analyze", "verify",
		"nftfw-early.service", "nftfw-enforcement-ready.service",
		"nftfwd.service", "nftfw-rollback.service", "nftfw-rollback.timer",
		"nftfw-setup-rollback.service", "nftfw-setup-rollback.timer",
		"nftfw-vpn.service", "nftfw-web.service"); err != nil {
		return errors.New("SETUP_SYSTEMD_VERIFY_FAILED")
	}
	if private.Intent.DockerEnabled {
		if err := containers.ValidateManagedDaemonConfig(s.Paths.DockerDaemon); err != nil {
			return err
		}
		if err := containers.ValidateManagedSocketDropIn(s.Paths.DockerDropIn); err != nil {
			return err
		}
	}
	return nil
}

func sameDockerNetworks(left, right []config.DockerNetwork) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}

func (s *System) ConfigureDocker(ctx context.Context, plan Plan) error {
	s.defaults()
	private, err := privatePlan(plan)
	if err != nil {
		return err
	}
	if !private.Intent.DockerEnabled {
		return nil
	}
	if err := containers.ValidateManagedDaemonConfig(s.Paths.DockerDaemon); err != nil {
		return err
	}
	if err := containers.ValidateManagedSocketDropIn(s.Paths.DockerDropIn); err != nil {
		return err
	}
	restartRequired := private.DockerChanged || plan.ResumeReady
	if restartRequired {
		if s.ConfirmDockerRestart == nil {
			return errors.New("SETUP_DOCKER_RESTART_CONFIRMATION_REQUIRED")
		}
		if err := s.ConfirmDockerRestart(plan.Summary); err != nil {
			return err
		}
	}
	// The reboot generator keeps Docker inactive. Release it only after the
	// managed daemon config, forwarding value, and immediate restart consent
	// are all durable.
	if plan.ResumeReady {
		if err := s.releaseDockerHold(); err != nil {
			return err
		}
	}
	if restartRequired {
		if _, err := s.Runner.Run(ctx, nil, "systemctl", "restart", "docker.service"); err != nil {
			return errors.New("SETUP_DOCKER_RESTART_FAILED")
		}
	} else if _, err := s.Runner.Run(ctx, nil, "systemctl", "is-active", "--quiet", "docker.service"); err != nil {
		return errors.New("SETUP_DOCKER_INACTIVE")
	}
	if err := containers.ValidateManagedDaemonConfig(s.Paths.DockerDaemon); err != nil {
		return err
	}
	if err := containers.ValidateManagedSocketDropIn(s.Paths.DockerDropIn); err != nil {
		return err
	}
	forwarding, err := s.Runner.Run(ctx, nil, "sysctl", "-n", "net.ipv4.ip_forward")
	if err != nil || strings.TrimSpace(string(forwarding)) != "1" {
		return errors.New("SETUP_DOCKER_IPV4_FORWARDING_FAILED")
	}
	observer := containers.Observer{
		Expected: private.Intent.DockerNetworks,
		Run: func(ctx context.Context, limit int64, name string, args ...string) ([]byte, error) {
			data, err := s.Runner.Run(ctx, nil, name, args...)
			if err != nil {
				return nil, err
			}
			if int64(len(data)) > limit {
				return nil, errors.New("SETUP_DOCKER_OUTPUT_TOO_LARGE")
			}
			return data, nil
		},
	}
	if _, err := observer.Networks(ctx); err != nil {
		return errors.New("SETUP_DOCKER_TOPOLOGY_CHANGED")
	}
	return nil
}

func (s *System) StartRuntime(ctx context.Context, _ Plan) error {
	s.defaults()
	if _, err := s.Runner.Run(ctx, nil, "systemctl", "enable", "--now", "nftfw-rollback.timer"); err != nil {
		return errors.New("SETUP_ROLLBACK_TIMER_FAILED")
	}
	if _, err := s.Runner.Run(ctx, nil, "systemctl", "start", "nftfwd.service"); err != nil {
		return errors.New("SETUP_DAEMON_START_FAILED")
	}
	ready := s.RuntimeReady
	if ready == nil {
		ready = s.runtimeReady
	}
	timeout := s.RuntimeReadyTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	poll := s.RuntimeReadyPoll
	if poll <= 0 {
		poll = 100 * time.Millisecond
	}
	deadline := time.Now().Add(timeout)
	for {
		if err := ready(ctx); err == nil {
			return nil
		} else if !errors.Is(err, errRuntimeStarting) {
			return err
		}
		if !time.Now().Before(deadline) {
			return errors.New("SETUP_DAEMON_READINESS_TIMEOUT")
		}
		select {
		case <-ctx.Done():
			return errors.New("SETUP_DAEMON_READINESS_CANCELED")
		case <-time.After(poll):
		}
	}
}

func (s *System) runtimeReady(ctx context.Context) error {
	if err := s.runtimeProcessReady(ctx); err != nil {
		return err
	}
	if err := s.runtimeSocketContracts(s.expectedRuntimeUID()); err != nil {
		return err
	}
	return s.runtimeAPIReady(ctx)
}

func (s *System) runtimeAPIReady(ctx context.Context) error {
	status, err := s.status(ctx)
	if err != nil {
		return errRuntimeStarting
	}
	if err := validateRuntimeSnapshot(status); err != nil {
		return err
	}
	data, err := s.control(ctx, api.Request{Op: "status"})
	if err != nil {
		return errRuntimeStarting
	}
	controlStatus, err := decodeRuntimeSnapshot(data)
	if err != nil {
		return err
	}
	return validateRuntimeSnapshot(controlStatus)
}

func (s *System) runtimeProcessReady(ctx context.Context) error {
	data, err := s.Runner.Run(ctx, nil, "systemctl", "show",
		"--property=MainPID,ActiveState,SubState", "nftfwd.service")
	if err != nil || len(data) == 0 || len(data) > 4096 {
		return errors.New("SETUP_DAEMON_STATE_FAILED")
	}
	values, err := parseRuntimeProperties(data)
	if err != nil {
		return err
	}
	if values["ActiveState"] == "activating" ||
		values["ActiveState"] == "active" && values["SubState"] == "start" {
		return errRuntimeStarting
	}
	if values["ActiveState"] != "active" || values["SubState"] != "running" {
		return errors.New("SETUP_DAEMON_NOT_RUNNING")
	}
	pid, err := strconv.ParseInt(values["MainPID"], 10, 32)
	if err != nil || pid <= 1 {
		return errRuntimeStarting
	}
	processRoot := s.runtimeProcessRoot
	if processRoot == "" {
		processRoot = "/proc"
	}
	expectedUID := s.expectedRuntimeUID()
	process := filepath.Join(processRoot, strconv.FormatInt(pid, 10))
	info, err := os.Stat(process)
	if errors.Is(err, os.ErrNotExist) {
		return errRuntimeStarting
	}
	stat, ok := func() (*syscall.Stat_t, bool) {
		if err != nil || !info.IsDir() {
			return nil, false
		}
		value, valid := info.Sys().(*syscall.Stat_t)
		return value, valid
	}()
	if !ok || stat.Uid != expectedUID {
		return errors.New("SETUP_DAEMON_PROCESS_UNSAFE")
	}
	executable, err := os.Readlink(filepath.Join(process, "exe"))
	if err != nil {
		return errRuntimeStarting
	}
	return validateRuntimeExecutable(executable)
}

func (s *System) expectedRuntimeUID() uint32 {
	if s.runtimeProcessUID != nil {
		return *s.runtimeProcessUID
	}
	return 0
}

func validateRuntimeExecutable(executable string) error {
	switch executable {
	case "/usr/lib/nftfw/nftfwd":
		return nil
	case "/usr/lib/systemd/systemd-executor":
		// systemd 257 can report the freshly forked, root-owned executor as the
		// service MainPID for a short interval before execve publishes nftfwd.
		return errRuntimeStarting
	default:
		return errors.New("SETUP_DAEMON_PROCESS_UNSAFE")
	}
}

func parseRuntimeProperties(data []byte) (map[string]string, error) {
	want := map[string]bool{"MainPID": true, "ActiveState": true, "SubState": true}
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		key, value, found := strings.Cut(line, "=")
		if !found || !want[key] || value == "" || len(value) > 128 {
			return nil, errors.New("SETUP_DAEMON_STATE_INVALID")
		}
		if _, duplicate := values[key]; duplicate {
			return nil, errors.New("SETUP_DAEMON_STATE_INVALID")
		}
		values[key] = value
	}
	if len(values) != len(want) {
		return nil, errors.New("SETUP_DAEMON_STATE_INVALID")
	}
	return values, nil
}

func (s *System) runtimeSocketContracts(expectedUID uint32) error {
	parent := filepath.Dir(s.Paths.StatusSocket)
	if parent != filepath.Dir(s.Paths.ControlSocket) || !filepath.IsAbs(parent) || filepath.Clean(parent) != parent {
		return errors.New("SETUP_DAEMON_SOCKET_UNSAFE")
	}
	info, err := os.Lstat(parent)
	if errors.Is(err, os.ErrNotExist) {
		return errRuntimeStarting
	}
	stat, ok := func() (*syscall.Stat_t, bool) {
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o750 {
			return nil, false
		}
		value, valid := info.Sys().(*syscall.Stat_t)
		return value, valid
	}()
	if !ok || stat.Uid != expectedUID {
		return errors.New("SETUP_DAEMON_SOCKET_UNSAFE")
	}
	for path, mode := range map[string]os.FileMode{
		s.Paths.StatusSocket: 0o660, s.Paths.ControlSocket: 0o600,
	} {
		socket, socketErr := os.Lstat(path)
		if errors.Is(socketErr, os.ErrNotExist) {
			return errRuntimeStarting
		}
		socketStat, valid := func() (*syscall.Stat_t, bool) {
			if socketErr != nil || socket.Mode()&os.ModeSymlink != 0 ||
				socket.Mode()&os.ModeSocket == 0 || socket.Mode().Perm() != mode {
				return nil, false
			}
			value, valid := socket.Sys().(*syscall.Stat_t)
			return value, valid
		}()
		if !valid || socketStat.Uid != expectedUID || socketStat.Gid != stat.Gid {
			return errors.New("SETUP_DAEMON_SOCKET_UNSAFE")
		}
	}
	return nil
}

func decodeRuntimeSnapshot(data any) (health.Snapshot, error) {
	encoded, err := json.Marshal(data)
	if err != nil {
		return health.Snapshot{}, errors.New("SETUP_DAEMON_STATUS_INVALID")
	}
	var snapshot health.Snapshot
	if json.Unmarshal(encoded, &snapshot) != nil {
		return health.Snapshot{}, errors.New("SETUP_DAEMON_STATUS_INVALID")
	}
	return snapshot, nil
}

func validateRuntimeSnapshot(snapshot health.Snapshot) error {
	if snapshot.Schema != health.StatusSchema || snapshot.Version == "" {
		return errors.New("SETUP_DAEMON_STATUS_INVALID")
	}
	if snapshot.Status == "HEALTHY" && snapshot.Active && snapshot.PolicyMatch &&
		snapshot.KillSwitchEnforced {
		return nil
	}
	// A clean first setup has no generation until the following safe-apply
	// phase. Accept only that exact, non-active bootstrap state; every degraded
	// established runtime remains a hard failure.
	bootstrap := snapshot.Status == "DEGRADED" && snapshot.Managed &&
		snapshot.Database == "ok" && !snapshot.Active && !snapshot.PolicyMatch &&
		!snapshot.KillSwitchEnforced && snapshot.ActiveGeneration == 0 &&
		snapshot.PendingGeneration == 0 &&
		(snapshot.Reason == "monotonic provenance ledger has no active mappings" ||
			snapshot.Reason == "no applied or committed policy generation exists")
	if bootstrap {
		return nil
	}
	return errors.New("SETUP_DAEMON_DEGRADED")
}

func (s *System) ApplySafe(ctx context.Context, _ Plan) (uint64, error) {
	s.defaults()
	data, err := s.control(ctx, api.Request{Op: "apply", Safe: true})
	if err != nil {
		return 0, errors.New("SETUP_SAFE_APPLY_FAILED")
	}
	encoded, err := json.Marshal(data)
	if err != nil {
		return 0, errors.New("SETUP_APPLY_RESPONSE_INVALID")
	}
	var result reconcile.Result
	if json.Unmarshal(encoded, &result) != nil || result.Generation == 0 || result.Committed {
		return 0, errors.New("SETUP_APPLY_RESPONSE_INVALID")
	}
	return result.Generation, nil
}

func (s *System) StartTunnel(ctx context.Context, plan Plan) error {
	s.defaults()
	private, err := privatePlan(plan)
	if err != nil {
		return err
	}
	return routing.Manager{Runner: s.Runner}.Up(ctx, private.Route)
}

func (s *System) Validate(ctx context.Context, plan Plan, generation uint64) error {
	s.defaults()
	private, err := privatePlan(plan)
	if err != nil || generation == 0 {
		return errors.New("SETUP_VALIDATION_INPUT_INVALID")
	}
	if s.ValidateHook != nil {
		return s.ValidateHook(ctx, *private, generation)
	}
	manager := routing.Manager{Runner: s.Runner}
	timeout := s.ValidationTimeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	poll := s.ValidationPoll
	if poll <= 0 {
		poll = time.Second
	}
	deadline := time.Now().Add(timeout)
	for {
		status, statusErr := manager.Status(ctx, private.Route)
		if statusErr == nil && status["healthy"] == true {
			break
		}
		if !time.Now().Before(deadline) {
			return errors.New("SETUP_WIREGUARD_HANDSHAKE_FAILED")
		}
		select {
		case <-ctx.Done():
			return errors.New("SETUP_VALIDATION_CANCELED")
		case <-time.After(poll):
		}
	}
	route, err := s.Runner.Run(ctx, nil, "ip", "-j", "-4", "route", "get", "1.1.1.1")
	if err != nil || routeDevice(route) != plan.Summary.VPNInterface {
		return errors.New("SETUP_VPN_ROUTE_VALIDATION_FAILED")
	}
	connectivity := s.Connectivity
	if connectivity == nil {
		connectivity = func(ctx context.Context) error {
			dialer := net.Dialer{Timeout: 8 * time.Second}
			connection, err := dialer.DialContext(ctx, "tcp4", "1.1.1.1:443")
			if err == nil {
				_ = connection.Close()
			}
			return err
		}
	}
	if err := connectivity(ctx); err != nil {
		return errors.New("SETUP_VPN_CONNECTIVITY_FAILED")
	}
	if len(private.Profile.DNS) > 0 {
		dnsCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
		defer cancel()
		lookup := s.DNSLookup
		if lookup == nil {
			lookup = net.DefaultResolver.LookupHost
		}
		if _, err := lookup(dnsCtx, "example.com"); err != nil {
			return errors.New("SETUP_VPN_DNS_FAILED")
		}
	}
	if private.Intent.DockerEnabled {
		if err := containers.ValidateManagedDaemonConfig(s.Paths.DockerDaemon); err != nil {
			return err
		}
		if err := containers.ValidateManagedSocketDropIn(s.Paths.DockerDropIn); err != nil {
			return err
		}
		forwarding, err := s.Runner.Run(ctx, nil, "sysctl", "-n", "net.ipv4.ip_forward")
		if err != nil || strings.TrimSpace(string(forwarding)) != "1" {
			return errors.New("SETUP_DOCKER_IPV4_FORWARDING_FAILED")
		}
		observer := containers.Observer{
			Expected: private.Intent.DockerNetworks,
			Run: func(ctx context.Context, limit int64, name string, args ...string) ([]byte, error) {
				data, err := s.Runner.Run(ctx, nil, name, args...)
				if err != nil {
					return nil, err
				}
				if int64(len(data)) > limit {
					return nil, errors.New("SETUP_DOCKER_OUTPUT_TOO_LARGE")
				}
				return data, nil
			},
		}
		observed, err := observer.Networks(ctx)
		if err != nil {
			return errors.New("SETUP_DOCKER_VALIDATION_FAILED")
		}
		if err := s.validateDockerRouting(ctx, observed, plan.Summary.VPNInterface); err != nil {
			return err
		}
	}
	return nil
}

func (s *System) validateDockerRouting(
	ctx context.Context, networks []containers.Network, vpnInterface string,
) error {
	for _, network := range networks {
		source, err := dockerRouteSource(network.CIDR, network.Gateway)
		if err != nil {
			return errors.New("SETUP_DOCKER_ROUTE_SOURCE_INVALID")
		}
		route, err := s.Runner.Run(
			ctx, nil, "ip", "-j", "-4", "route", "get", "1.1.1.1",
			"from", source.String(), "iif", network.BridgeInterface,
		)
		if err != nil || routeDevice(route) != vpnInterface {
			return errors.New("SETUP_DOCKER_ROUTE_VALIDATION_FAILED")
		}
	}
	return nil
}

func dockerRouteSource(cidr, rawGateway string) (netip.Addr, error) {
	prefix, err := netip.ParsePrefix(cidr)
	gateway, gatewayErr := netip.ParseAddr(rawGateway)
	if err != nil || gatewayErr != nil || !prefix.Addr().Is4() ||
		!gateway.Is4() || prefix.Bits() == 0 || prefix.Bits() > 30 {
		return netip.Addr{}, errors.New("invalid Docker route source")
	}
	prefix = prefix.Masked()
	candidate := prefix.Addr().Next()
	if candidate == gateway {
		candidate = candidate.Next()
	}
	if !candidate.IsValid() || !prefix.Contains(candidate) || candidate == gateway {
		return netip.Addr{}, errors.New("invalid Docker route source")
	}
	return candidate, nil
}

func (s *System) Commit(ctx context.Context, _ Plan, generation uint64) error {
	if generation == 0 {
		return errors.New("SETUP_GENERATION_INVALID")
	}
	if _, err := s.control(ctx, api.Request{Op: "commit", Generation: generation}); err != nil {
		return errors.New("SETUP_COMMIT_FAILED")
	}
	return nil
}

func (s *System) GenerationCommitted(ctx context.Context, generation uint64) (bool, error) {
	if generation == 0 {
		return false, errors.New("SETUP_GENERATION_INVALID")
	}
	s.defaults()
	snapshot, err := s.status(ctx)
	if err != nil {
		return false, errors.New("SETUP_COMMIT_STATE_UNKNOWN")
	}
	return snapshot.ActiveGeneration == generation && snapshot.PendingGeneration == 0 &&
		snapshot.Active && snapshot.PolicyMatch && snapshot.KillSwitchEnforced, nil
}

// PublishFinalDependencies converts the already committed runtime into its
// durable boot relationship. The daemon was intentionally started without
// these Requisite edges during first setup; publishing them any earlier would
// make that runtime start impossible while nftfw-early is still inactive.
func (s *System) PublishFinalDependencies(ctx context.Context, plan Plan) error {
	s.defaults()
	for _, unit := range []string{"nftfw-early.service", "nftfw-enforcement-ready.service"} {
		if _, err := s.Runner.Run(ctx, nil, "systemctl", "start", unit); err != nil {
			return errors.New("SETUP_EARLY_ENFORCEMENT_FAILED")
		}
	}
	managerAction := "rebuild-enabled"
	if plan.Summary.BootPolicy == ManagedBootPolicy {
		managerAction = "verify-enabled"
	}
	if _, err := s.Runner.Run(ctx, nil, s.Paths.InitramfsManager, managerAction); err != nil {
		return errors.New("SETUP_INITRAMFS_GUARD_FAILED")
	}
	for _, path := range []string{
		filepath.Join(s.Paths.SystemdDir, "nftfwd.service.d", "50-nftfw-final-early.conf"),
		filepath.Join(s.Paths.SystemdDir, "nftfw-rollback.service.d", "50-nftfw-final-early.conf"),
	} {
		if err := writeAtomic(path, []byte(finalEarlyDropIn), 0o644); err != nil {
			return errors.New("SETUP_FINAL_DEPENDENCY_PUBLISH_FAILED")
		}
	}
	if _, err := s.Runner.Run(ctx, nil, "systemctl", "daemon-reload"); err != nil {
		return errors.New("SETUP_FINAL_DEPENDENCY_RELOAD_FAILED")
	}
	if plan.Summary.BootPolicy == ManagedBootPolicy {
		private, err := privatePlan(plan)
		if err != nil || private.BackupDir == "" {
			return errors.New("SETUP_BOOT_HOLD_STATE_INVALID")
		}
		if err := restoreBackupFiles(private.BackupDir, []string{s.Paths.BootHoldMarker}); err != nil {
			return errors.New("SETUP_BOOT_HOLD_RESTORE_FAILED")
		}
		if err := s.removeResumeGuard(ctx); err != nil {
			return err
		}
		if err := s.cleanupDockerHold(ctx); err != nil {
			return err
		}
		if err := s.releaseBootHold(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (s *System) EnableBoot(ctx context.Context, _ Plan) error {
	s.defaults()
	units := []string{
		"nftfw-early.service", "nftfw-enforcement-ready.service", "nftfwd.service",
		"nftfw-rollback.timer", "nftfw-web.service", "nftfw-vpn.service",
	}
	args := append([]string{"enable"}, units...)
	if _, err := s.Runner.Run(ctx, nil, "systemctl", args...); err != nil {
		return errors.New("SETUP_BOOT_ENABLE_FAILED")
	}
	for _, unit := range []string{"nftfw-vpn.service", "nftfw-web.service"} {
		if _, err := s.Runner.Run(ctx, nil, "systemctl", "start", unit); err != nil {
			return errors.New("SETUP_BOOT_ACTIVATION_FAILED")
		}
	}
	if _, err := s.Runner.Run(ctx, nil, "systemctl", "restart", "nftfwd.service"); err != nil {
		return errors.New("SETUP_DAEMON_FINAL_RESTART_FAILED")
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		snapshot, err := s.status(ctx)
		if err == nil && snapshot.Status == "HEALTHY" && snapshot.Active &&
			snapshot.PolicyMatch && snapshot.KillSwitchEnforced {
			return nil
		}
		if !time.Now().Before(deadline) {
			return errors.New("SETUP_FINAL_HEALTH_FAILED")
		}
		select {
		case <-ctx.Done():
			return errors.New("SETUP_FINAL_HEALTH_CANCELED")
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func (s *System) Finalize(ctx context.Context, plan Plan) error {
	s.defaults()
	if _, err := s.Runner.Run(ctx, nil, "nft", "delete", "table", "inet", "nftfw_setup_guard"); err != nil {
		if _, existsErr := s.Runner.Run(ctx, nil, "nft", "list", "table", "inet", "nftfw_setup_guard"); existsErr == nil {
			return errors.New("SETUP_GUARD_REMOVE_FAILED")
		}
	}
	if plan.Summary.BootPolicy == ManagedBootPolicy {
		if err := s.removeResumeGuard(ctx); err != nil {
			return err
		}
	}
	_ = os.Remove(filepath.Join(s.Paths.RuntimeDir, "setup-guard.nft"))
	if _, err := s.Runner.Run(ctx, nil, "systemctl", "disable", "--now", "nftfw-setup-rollback.timer"); err != nil {
		return errors.New("SETUP_WATCHDOG_STOP_FAILED")
	}
	report := []byte("NFT Firewall V2 managed setup: COMPLETE\n")
	if err := writeAtomic(filepath.Join(s.Paths.StateDir, "setup", "LAST_SUCCESS"), report, 0o600); err != nil {
		return err
	}
	return nil
}

func (s *System) Rollback(ctx context.Context, plan Plan, journal Journal) error {
	s.defaults()
	// Inspect and incomplete-backup journals precede the first protected-state
	// mutation. They can be terminally recorded without stopping services or
	// attempting to restore a backup that was never durably established.
	if journalBeforeProtectedMutation(journal) {
		return nil
	}
	backupDir := journal.BackupDir
	if backupDir == "" {
		if private, err := privatePlan(plan); err == nil {
			backupDir = private.BackupDir
		}
	}
	// Once a mutation-capable phase is recorded, recovery must prove both the
	// prepared-plan identity and its durable backup before touching services.
	// A missing boundary is ambiguous state and must fail closed in place.
	if backupDir == "" {
		return errors.New("SETUP_ROLLBACK_BACKUP_MISSING")
	}
	summary := plan.Summary
	if summary.Schema == "" {
		summary = journal.Summary
	}
	if summary.Schema != "nftfw.setup-plan.v1" {
		return errors.New("SETUP_ROLLBACK_PLAN_INVALID")
	}
	route, err := managedRollbackRoute(summary)
	if err != nil {
		return err
	}
	var failures []string
	if phaseMayHaveTunnel(journal.Phase) {
		if err := (routing.Manager{Runner: s.Runner}).Down(ctx, route); err != nil {
			failures = append(failures, "tunnel")
		}
	}
	if journal.Generation != 0 && !journal.Committed {
		if _, err := s.control(ctx, api.Request{Op: "rollback", Generation: journal.Generation}); err != nil {
			failures = append(failures, "generation")
		}
	}
	for _, unit := range []string{
		"nftfw-vpn.service", "nftfw-web.service", "nftfwd.service",
		"nftfw-enforcement-ready.service", "nftfw-early.service",
		"nftfw-rollback.timer", "nftfw-setup-rollback.timer",
	} {
		_, _ = s.Runner.Run(ctx, nil, "systemctl", "stop", unit)
	}
	bootRollback := false
	if manifest, manifestErr := readBackup(backupDir); manifestErr != nil {
		failures = append(failures, "boot-state")
	} else if manifest.Boot != nil {
		bootRollback = true
		if _, err := s.Runner.Run(ctx, nil, s.Paths.InitramfsManager, "disable"); err != nil {
			failures = append(failures, "initramfs")
		}
	}
	if bootRollback && summary.DockerMode == "enabled" {
		generated, holdErr := s.dockerHoldGenerated()
		if holdErr != nil {
			return errors.New("SETUP_ROLLBACK_INCOMPLETE_DOCKER_HOLD")
		}
		if generated {
			if err := restoreBackupFiles(backupDir, []string{s.Paths.DockerDaemon, s.Paths.DockerDropIn}); err != nil {
				return errors.New("SETUP_ROLLBACK_INCOMPLETE_DOCKER_HOLD_RESTORE")
			}
			if _, err := s.Runner.Run(ctx, nil, "systemctl", "daemon-reload"); err != nil {
				return errors.New("SETUP_ROLLBACK_INCOMPLETE_DOCKER_HOLD_RELOAD")
			}
			if err := s.releaseDockerHold(); err != nil {
				return errors.New("SETUP_ROLLBACK_INCOMPLETE_DOCKER_HOLD_RELEASE")
			}
		}
	}
	deferIPv6Restore := bootRollback && runningKernelHasManagedDisable(s.Paths)
	var deferSysctl func(string) bool
	if deferIPv6Restore {
		deferSysctl = bootIPv6Sysctl
	}
	if err := restoreBackupDeferring(ctx, s.Runner, backupDir, deferSysctl); err != nil {
		failures = append(failures, "restore")
	}
	_, _ = s.Runner.Run(ctx, nil, "systemctl", "daemon-reload")
	if _, err := s.Runner.Run(ctx, nil, "nft", "delete", "table", "inet", "nftfw_setup_guard"); err != nil {
		if _, existsErr := s.Runner.Run(ctx, nil, "nft", "list", "table", "inet", "nftfw_setup_guard"); existsErr == nil {
			failures = append(failures, "guard")
		}
	}
	if bootRollback {
		if err := s.removeResumeGuard(ctx); err != nil {
			failures = append(failures, "resume-guard")
		}
		if err := s.cleanupDockerHold(ctx); err != nil {
			failures = append(failures, "docker-hold")
		}
	}
	if len(failures) > 0 {
		sort.Strings(failures)
		return fmt.Errorf("SETUP_ROLLBACK_INCOMPLETE_%s", strings.ToUpper(strings.Join(failures, "_")))
	}
	if bootRollback {
		if err := s.releaseBootHold(ctx); err != nil {
			return err
		}
	}
	if deferIPv6Restore {
		return ErrRollbackRebootRequired
	}
	return nil
}

func managedRollbackRoute(summary Summary) (routing.Config, error) {
	resolver := routing.ResolverMode(summary.ResolverMode)
	if summary.VPNInterface != intent.VPNInterface ||
		(resolver != routing.ResolverNone && resolver != routing.ResolverResolvectl &&
			resolver != routing.ResolverResolvconf) {
		return routing.Config{}, errors.New("SETUP_ROLLBACK_PLAN_INVALID")
	}
	return routing.Config{
		Interface: intent.VPNInterface, Fwmark: intent.VPNFwmark,
		Table: routing.DefaultTable, Resolver: resolver,
	}, nil
}

func phaseMayHaveTunnel(phase Phase) bool {
	switch phase {
	case PhaseTunnel, PhaseValidate, PhaseCommit, PhaseHandoff, PhaseBoot, PhaseFinalize,
		PhaseComplete, PhaseRollback, PhaseFailed:
		return true
	default:
		return false
	}
}

func (s *System) RecoverCommitted(ctx context.Context, plan Plan, _ Journal) error {
	if err := s.PublishFinalDependencies(ctx, plan); err != nil {
		return err
	}
	if err := s.EnableBoot(ctx, plan); err != nil {
		return err
	}
	return s.Finalize(ctx, plan)
}

func (s *System) defaults() {
	defaults := DefaultPaths()
	if s.Paths.Config == "" {
		s.Paths.Config = defaults.Config
	}
	if s.Paths.Intent == "" {
		s.Paths.Intent = defaults.Intent
	}
	if s.Paths.VPN == "" {
		s.Paths.VPN = defaults.VPN
	}
	if s.Paths.Sysctl == "" {
		s.Paths.Sysctl = defaults.Sysctl
	}
	if s.Paths.StateDir == "" {
		s.Paths.StateDir = defaults.StateDir
	}
	if s.Paths.RuntimeDir == "" {
		s.Paths.RuntimeDir = defaults.RuntimeDir
	}
	if s.Paths.SystemdDir == "" {
		s.Paths.SystemdDir = defaults.SystemdDir
	}
	if s.Paths.DockerDaemon == "" {
		s.Paths.DockerDaemon = defaults.DockerDaemon
	}
	if s.Paths.DockerDropIn == "" {
		s.Paths.DockerDropIn = defaults.DockerDropIn
	}
	if s.Paths.InitramfsMarker == "" {
		s.Paths.InitramfsMarker = defaults.InitramfsMarker
	}
	if s.Paths.InitramfsOwner == "" {
		s.Paths.InitramfsOwner = defaults.InitramfsOwner
	}
	if s.Paths.InitramfsLoader == "" {
		s.Paths.InitramfsLoader = defaults.InitramfsLoader
	}
	if s.Paths.InitramfsGate == "" {
		s.Paths.InitramfsGate = defaults.InitramfsGate
	}
	if s.Paths.InitramfsManager == "" {
		s.Paths.InitramfsManager = defaults.InitramfsManager
	}
	if s.Paths.GRUBFragment == "" {
		s.Paths.GRUBFragment = defaults.GRUBFragment
	}
	if s.Paths.GRUBSourceDir == "" {
		s.Paths.GRUBSourceDir = defaults.GRUBSourceDir
	}
	if s.Paths.GRUBGenerated == "" {
		s.Paths.GRUBGenerated = defaults.GRUBGenerated
	}
	if s.Paths.GRUBUpdate == "" {
		s.Paths.GRUBUpdate = defaults.GRUBUpdate
	}
	if s.Paths.BootKernelDir == "" {
		s.Paths.BootKernelDir = defaults.BootKernelDir
	}
	if s.Paths.ProcCmdline == "" {
		s.Paths.ProcCmdline = defaults.ProcCmdline
	}
	if s.Paths.ProcBootID == "" {
		s.Paths.ProcBootID = defaults.ProcBootID
	}
	if s.Paths.IPv6DisableParam == "" {
		s.Paths.IPv6DisableParam = defaults.IPv6DisableParam
	}
	if s.Paths.ProcIfInet6 == "" {
		s.Paths.ProcIfInet6 = defaults.ProcIfInet6
	}
	if s.Paths.SystemdBootEntries == "" {
		s.Paths.SystemdBootEntries = defaults.SystemdBootEntries
	}
	if s.Paths.UKIDir == "" {
		s.Paths.UKIDir = defaults.UKIDir
	}
	if s.Paths.ExtlinuxDir == "" {
		s.Paths.ExtlinuxDir = defaults.ExtlinuxDir
	}
	if s.Paths.AlternateGRUBDir == "" {
		s.Paths.AlternateGRUBDir = defaults.AlternateGRUBDir
	}
	if s.Paths.EFIFirmwareDir == "" {
		s.Paths.EFIFirmwareDir = defaults.EFIFirmwareDir
	}
	if s.Paths.EFIBootManager == "" {
		s.Paths.EFIBootManager = defaults.EFIBootManager
	}
	if s.Paths.BootHoldMarker == "" {
		s.Paths.BootHoldMarker = defaults.BootHoldMarker
	}
	if s.Paths.BootHoldReady == "" {
		s.Paths.BootHoldReady = defaults.BootHoldReady
	}
	if s.Paths.BootHoldRelease == "" {
		s.Paths.BootHoldRelease = defaults.BootHoldRelease
	}
	if s.Paths.DockerHoldReady == "" {
		s.Paths.DockerHoldReady = defaults.DockerHoldReady
	}
	if s.Paths.DockerHoldRelease == "" {
		s.Paths.DockerHoldRelease = defaults.DockerHoldRelease
	}
	if s.Paths.DockerHoldService == "" {
		s.Paths.DockerHoldService = defaults.DockerHoldService
	}
	if s.Paths.DockerHoldSocket == "" {
		s.Paths.DockerHoldSocket = defaults.DockerHoldSocket
	}
	if s.Paths.ControlSocket == "" {
		s.Paths.ControlSocket = defaults.ControlSocket
	}
	if s.Paths.StatusSocket == "" {
		s.Paths.StatusSocket = defaults.StatusSocket
	}
	if s.Runner == nil {
		s.Runner = routing.ExecRunner{}
	}
}

func (s *System) control(ctx context.Context, request api.Request) (any, error) {
	if s.Control != nil {
		return s.Control(ctx, request)
	}
	response, err := api.Call(ctx, s.Paths.ControlSocket, request)
	if err != nil {
		return nil, err
	}
	return response.Data, nil
}

func (s *System) status(ctx context.Context) (health.Snapshot, error) {
	if s.Status != nil {
		return s.Status(ctx)
	}
	response, err := api.Call(ctx, s.Paths.StatusSocket, api.Request{Op: "status"})
	if err != nil {
		return health.Snapshot{}, err
	}
	encoded, err := json.Marshal(response.Data)
	if err != nil {
		return health.Snapshot{}, err
	}
	var snapshot health.Snapshot
	if json.Unmarshal(encoded, &snapshot) != nil {
		return health.Snapshot{}, errors.New("status decode failed")
	}
	return snapshot, nil
}

func (s *System) touchedFiles(plan Plan) []string {
	result := []string{
		s.Paths.VPN, s.Paths.Intent, s.Paths.Config, s.Paths.Sysctl, s.Paths.InitramfsMarker,
		s.Paths.InitramfsOwner, s.Paths.InitramfsLoader, s.Paths.InitramfsGate,
		filepath.Join(s.Paths.SystemdDir, "nftfwd.service.d", "50-nftfw-final-early.conf"),
		filepath.Join(s.Paths.SystemdDir, "nftfw-rollback.service.d", "50-nftfw-final-early.conf"),
	}
	if plan.Summary.BootPolicy == ManagedBootPolicy {
		result = append(result, s.Paths.GRUBFragment, s.Paths.GRUBGenerated, s.Paths.BootHoldMarker)
	}
	if plan.Summary.DockerMode == "enabled" {
		result = append(result, s.Paths.DockerDaemon, s.Paths.DockerDropIn)
	}
	return result
}

func privatePlan(plan Plan) (*prepared, error) {
	private, ok := plan.PrivateData.(*prepared)
	if !ok || private == nil {
		return nil, errors.New("SETUP_PRIVATE_PLAN_MISSING")
	}
	return private, nil
}

func resolveIPv4(ctx context.Context, host string) ([]netip.Addr, error) {
	if address, err := netip.ParseAddr(host); err == nil {
		if address.Is4() {
			return []netip.Addr{address}, nil
		}
		return nil, errors.New("IPv6 endpoint unsupported")
	}
	values, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var result []netip.Addr
	for _, address := range values {
		if address.Is4() && !address.IsUnspecified() && !address.IsLoopback() &&
			!address.IsMulticast() && !address.IsLinkLocalUnicast() && !seen[address.String()] {
			seen[address.String()] = true
			result = append(result, address)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Less(result[j]) })
	if len(result) == 0 || len(result) > 16 {
		return nil, errors.New("endpoint set invalid")
	}
	return result, nil
}

func routeDevice(data []byte) string {
	var routes []struct {
		Device string `json:"dev"`
	}
	if len(data) > 1<<20 || json.Unmarshal(data, &routes) != nil || len(routes) != 1 {
		return ""
	}
	return routes[0].Device
}

func renderSysctl(interfaces []string, dockerEnabled, kernelIPv6Disabled bool) []byte {
	var builder strings.Builder
	builder.WriteString("# Managed by NFT Firewall V2.\n")
	if dockerEnabled {
		builder.WriteString("net.ipv4.ip_forward = 1\n")
	}
	if kernelIPv6Disabled {
		return []byte(builder.String())
	}
	builder.WriteString("net.ipv6.conf.default.disable_ipv6 = 1\n")
	builder.WriteString("net.ipv6.conf.lo.disable_ipv6 = 1\n")
	for _, name := range interfaces {
		builder.WriteString("net.ipv6.conf." + name + ".disable_ipv6 = 1\n")
	}
	builder.WriteString("net.ipv6.conf.all.forwarding = 0\n")
	return []byte(builder.String())
}

func bootIPv6Sysctl(key string) bool {
	return strings.HasPrefix(key, "net.ipv6.")
}

func anyBackupSysctl(string) bool {
	return true
}

func managedUnits(dockerEnabled bool) []string {
	result := []string{
		"nftfw-early.service", "nftfw-enforcement-ready.service", "nftfwd.service",
		"nftfw-rollback.timer", "nftfw-web.service", "nftfw-vpn.service",
		"nftfw-setup-rollback.timer", "nftfw-managed-rollback.timer",
	}
	if dockerEnabled {
		result = append(result, "docker.service")
	}
	return result
}

func (s *System) managedUnitsForBackup(ctx context.Context, dockerEnabled bool) ([]string, error) {
	result := managedUnits(dockerEnabled)
	if !dockerEnabled {
		return result, nil
	}
	service, err := s.dockerBackupUnitState(ctx, "docker.service")
	if err != nil || service["LoadState"] != "loaded" || service["ActiveState"] != "active" {
		return nil, errors.New("SETUP_BACKUP_DOCKER_SERVICE_STATE_INVALID")
	}
	socket, err := s.dockerBackupUnitState(ctx, "docker.socket")
	if err != nil {
		return nil, err
	}
	switch {
	case socket["LoadState"] == "loaded" &&
		(socket["ActiveState"] == "active" || socket["ActiveState"] == "inactive"):
		return append(result, "docker.socket"), nil
	case socket["LoadState"] == "not-found" && socket["ActiveState"] == "inactive":
		return result, nil
	default:
		return nil, errors.New("SETUP_BACKUP_DOCKER_SOCKET_STATE_INVALID")
	}
}

func (s *System) dockerBackupUnitState(ctx context.Context, unit string) (map[string]string, error) {
	data, err := s.Runner.Run(ctx, nil, "systemctl", "show",
		"--property=LoadState,ActiveState", unit)
	if err != nil || len(data) == 0 || len(data) > 512 {
		return nil, errors.New("SETUP_BACKUP_DOCKER_UNIT_STATE_FAILED")
	}
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		key, value, found := strings.Cut(line, "=")
		if !found || (key != "LoadState" && key != "ActiveState") || value == "" || len(value) > 64 {
			return nil, errors.New("SETUP_BACKUP_DOCKER_UNIT_STATE_INVALID")
		}
		if _, duplicate := values[key]; duplicate {
			return nil, errors.New("SETUP_BACKUP_DOCKER_UNIT_STATE_INVALID")
		}
		values[key] = value
	}
	if len(values) != 2 {
		return nil, errors.New("SETUP_BACKUP_DOCKER_UNIT_STATE_INVALID")
	}
	return values, nil
}

func managedSysctls(interfaces []string, dockerEnabled bool) []string {
	result := []string{
		"net.ipv6.conf.default.disable_ipv6",
		"net.ipv6.conf.all.forwarding",
		"net.ipv6.conf.lo.disable_ipv6",
	}
	if dockerEnabled {
		result = append(result, "net.ipv4.ip_forward")
	}
	for _, name := range interfaces {
		result = append(result, "net.ipv6.conf."+name+".disable_ipv6")
	}
	return result
}

type discoveryAdapter struct {
	runner routing.Runner
}

func (d discoveryAdapter) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return d.runner.Run(ctx, nil, name, args...)
}

const finalEarlyDropIn = `[Unit]
Requisite=nftfw-early.service
After=nftfw-early.service
`
