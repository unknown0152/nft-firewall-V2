package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/unknown0152/nft-firewall-v2/internal/adoption"
	"github.com/unknown0152/nft-firewall-v2/internal/api"
	"github.com/unknown0152/nft-firewall-v2/internal/config"
	"github.com/unknown0152/nft-firewall-v2/internal/health"
	"github.com/unknown0152/nft-firewall-v2/internal/intent"
	"github.com/unknown0152/nft-firewall-v2/internal/operatorbackup"
	"github.com/unknown0152/nft-firewall-v2/internal/reconcile"
	"github.com/unknown0152/nft-firewall-v2/internal/routing"
	managedsetup "github.com/unknown0152/nft-firewall-v2/internal/setup"
	"github.com/unknown0152/nft-firewall-v2/internal/wgconfig"
)

var (
	managedIntentPath   = "/etc/nftfw/intent.toml"
	managedConfigPath   = "/etc/nftfw/nftfw.toml"
	managedVPNPath      = "/etc/wireguard/nftfw0.conf"
	setupJournalPath    = "/var/lib/nftfw/setup/journal.json"
	setupLockPath       = "/run/nftfw/setup.lock"
	managedStatusSock   = "/run/nftfw/status.sock"
	managedControlSock  = "/run/nftfw/control.sock"
	managedStateDB      = "/var/lib/nftfw/generation-state/state.db"
	managedLedger       = "/var/lib/nftfw/provenance-ledger.db"
	managedGenerations  = "/var/lib/nftfw/generations"
	managedEnforcement  = "/var/lib/nftfw/enforcement-enabled"
	managedSysctl       = "/etc/sysctl.d/90-nftfw-managed.conf"
	managedDockerDaemon = "/etc/docker/daemon.json"
	managedDockerDropIn = "/etc/systemd/system/nftfwd.service.d/docker-access.conf"
	managedStateRoot    = "/var/lib/nftfw"
	managedRuntimeRoot  = "/run/nftfw"

	managedEUID     = os.Geteuid
	managedAPICall  = api.Call
	managedTunnelUp = func(ctx context.Context, config routing.Config) error {
		return (routing.Manager{}).Up(ctx, config)
	}
	managedTunnelDown = func(ctx context.Context, config routing.Config) error {
		return (routing.Manager{}).Down(ctx, config)
	}
	managedTunnelStatus = func(ctx context.Context, config routing.Config) (map[string]any, error) {
		return (routing.Manager{}).Status(ctx, config)
	}
	managedAdoptionPlan = func(ctx context.Context, vpnPath string) (adoption.Plan, error) {
		inspector := adoption.SystemInspector{Paths: adoption.Paths{
			Config: managedConfigPath, Intent: managedIntentPath,
			DockerDaemon: managedDockerDaemon,
		}}
		return (adoption.Planner{Inspector: inspector}).Plan(ctx, vpnPath)
	}
)

func setupCommand(args []string) error {
	if len(args) > 0 && args[0] == "status" {
		if len(args) > 2 || (len(args) == 2 && args[1] != "--json") {
			return errors.New("usage: nftfw setup status [--json]")
		}
		journal, err := (managedsetup.FileJournal{Path: setupJournalPath}).Read()
		if err != nil {
			return err
		}
		if has(args, "--json") {
			return printJSONOr(journal, true)
		}
		fmt.Printf("Setup: %s\nPhase: %s\nTransaction: %s\n", journal.Status, journal.Phase, journal.Transaction)
		if journal.ErrorCode != "" {
			fmt.Printf("Last error: %s\n", journal.ErrorCode)
		}
		return nil
	}
	if len(args) > 0 && args[0] == "rollback" {
		return setupRollbackCommand(args[1:])
	}
	if len(args) > 0 && args[0] == "adopt" {
		return setupAdoptCommand(args[1:])
	}
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		return errors.New("usage: nftfw setup --vpn PATH [--dry-run] [--yes] [--json] | nftfw setup <status|rollback|adopt>")
	}
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	vpnPath := fs.String("vpn", "", "working WireGuard provider configuration")
	dryRun := fs.Bool("dry-run", false, "inspect and plan without changing the host")
	yes := fs.Bool("yes", false, "accept the generated clean-host plan")
	jsonMode := fs.Bool("json", false, "machine-readable output")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *vpnPath == "" {
		return errors.New("usage: nftfw setup --vpn PATH [--dry-run] [--yes] [--json]")
	}
	if managedEUID() != 0 {
		return errors.New("SETUP_REQUIRES_ROOT")
	}
	release, err := acquireSetupLock()
	if err != nil {
		return err
	}
	defer release()
	existing, existingSummary, err := existingManagedSetup(context.Background(), *vpnPath)
	if err != nil {
		return err
	}
	if existing {
		if *jsonMode {
			return printJSONOr(map[string]any{
				"status": "PROTECTED", "idempotent": true, "plan": existingSummary,
			}, true)
		}
		printProtectedSummary(existingSummary, true)
		return nil
	}
	system := &managedsetup.System{}
	if *yes {
		system.ConfirmDockerRestart = func(managedsetup.Summary) error { return nil }
	} else {
		system.ConfirmDockerRestart = confirmDockerRestart
	}
	engine := managedsetup.Engine{
		Executor: system, Journal: managedsetup.FileJournal{Path: setupJournalPath},
		Timeout: 15 * time.Minute,
	}
	if *dryRun {
		plan, err := engine.DryRun(context.Background(), *vpnPath)
		if err != nil {
			return err
		}
		if *jsonMode {
			return printJSONOr(plan.Summary, true)
		}
		printSetupSummary(plan.Summary)
		fmt.Println("No files, services, routes, VPN interfaces, or firewall rules were changed.")
		return nil
	}
	plan, err := engine.DryRun(context.Background(), *vpnPath)
	if err != nil {
		return err
	}
	if !*yes {
		printSetupSummary(plan.Summary)
		confirmed, err := confirmSetup()
		if err != nil {
			return err
		}
		if !confirmed {
			return errors.New("SETUP_CANCELED")
		}
	}
	plan, err = engine.Run(context.Background(), *vpnPath)
	if err != nil {
		return err
	}
	if *jsonMode {
		return printJSONOr(map[string]any{"status": "PROTECTED", "plan": plan.Summary}, true)
	}
	printProtectedSummary(plan.Summary, false)
	return nil
}

func setupAdoptCommand(args []string) error {
	fs := flag.NewFlagSet("setup adopt", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	vpnPath := fs.String("vpn", "", "working WireGuard provider configuration")
	dryRun := fs.Bool("dry-run", false, "produce a non-mutating adoption worksheet")
	jsonMode := fs.Bool("json", false, "machine-readable output")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *vpnPath == "" {
		return adoption.OperatorError(adoption.Error{Code: "ADOPTION_USAGE_INVALID"})
	}
	if !*dryRun {
		return adoption.OperatorError(adoption.Error{Code: "ADOPTION_EXECUTION_REQUIRES_SEPARATE_LIVE_PLAN"})
	}
	if managedEUID() != 0 {
		return adoption.OperatorError(adoption.Error{Code: "ADOPTION_REQUIRES_ROOT"})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	plan, err := managedAdoptionPlan(ctx, *vpnPath)
	if err != nil {
		return adoption.OperatorError(err)
	}
	if *jsonMode {
		return printJSONOr(plan, true)
	}
	fmt.Print(plan.Human())
	return nil
}

func setupRollbackCommand(args []string) error {
	fs := flag.NewFlagSet("setup rollback", flag.ContinueOnError)
	expiredOnly := fs.Bool("expired", false, "rollback only an expired running transaction")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return errors.New("usage: nftfw setup rollback [--expired]")
	}
	if managedEUID() != 0 {
		return errors.New("SETUP_REQUIRES_ROOT")
	}
	release, err := acquireSetupLock()
	if err != nil {
		return err
	}
	defer release()
	store := managedsetup.FileJournal{Path: setupJournalPath}
	journal, err := store.Read()
	if err != nil {
		return err
	}
	if journal.Status != "running" && journal.Status != "rolling_back" &&
		journal.Status != "recovering_committed" {
		return nil
	}
	if *expiredOnly && time.Now().UTC().Before(journal.Deadline) {
		return nil
	}
	system := &managedsetup.System{}
	plan := managedsetup.Plan{Summary: journal.Summary}
	if !journal.Committed && journal.Generation != 0 {
		committed, err := system.GenerationCommitted(context.Background(), journal.Generation)
		if err != nil {
			return err
		}
		journal.Committed = committed
	}
	if journal.Committed {
		if err := system.RecoverCommitted(context.Background(), plan, journal); err != nil {
			return err
		}
		journal.Status, journal.Phase = "complete", managedsetup.PhaseComplete
	} else {
		if err := system.Rollback(context.Background(), plan, journal); err != nil {
			return err
		}
		journal.Status, journal.Phase = "rolled_back", managedsetup.PhaseFailed
	}
	journal.UpdatedAt = time.Now().UTC()
	return store.Write(journal)
}

func tunnelCommand(args []string) error {
	if len(args) < 1 || len(args) > 2 || (len(args) == 2 && args[1] != "--json") {
		return errors.New("usage: nftfw tunnel <up|down|restart|status> [--json]")
	}
	command := args[0]
	if command != "status" && managedEUID() != 0 {
		return errors.New("TUNNEL_REQUIRES_ROOT")
	}
	config, err := loadRoutingConfig()
	if err != nil {
		return err
	}
	ctx := context.Background()
	switch command {
	case "up":
		status, statusErr := managedTunnelStatus(ctx, config)
		if statusErr == nil && status["healthy"] == true {
			return nil
		}
		return managedTunnelUp(ctx, config)
	case "down":
		status, statusErr := managedTunnelStatus(ctx, config)
		if statusErr == nil && status["active"] == false {
			return nil
		}
		return managedTunnelDown(ctx, config)
	case "restart":
		status, statusErr := managedTunnelStatus(ctx, config)
		if statusErr != nil || status["active"] == true {
			if err := managedTunnelDown(ctx, config); err != nil {
				return err
			}
		}
		return managedTunnelUp(ctx, config)
	case "status":
		status, err := managedTunnelStatus(ctx, config)
		if err != nil {
			return err
		}
		if has(args, "--json") {
			return printJSONOr(status, true)
		}
		fmt.Printf("Tunnel %s: active=%t healthy=%t\n", status["interface"], status["active"], status["healthy"])
		return nil
	default:
		return errors.New("usage: nftfw tunnel <up|down|restart|status> [--json]")
	}
}

func exposeCommand(args []string) error {
	operands, options, err := parseManagedMutationArgs(args)
	if err != nil || len(operands) < 3 || (operands[0] != "add" && operands[0] != "remove") {
		return errors.New("usage: nftfw expose <add|remove> <tcp|udp> PORTS [--dry-run] [--yes] [--json]")
	}
	ports, err := parsePorts(operands[2:])
	if err != nil {
		return err
	}
	action := "remove public " + operands[1]
	if operands[0] == "add" {
		action = "add public " + operands[1]
	}
	return changeManagedIntent(action, options, func(value *intent.Intent) error {
		if operands[0] == "add" {
			return value.AddExposure(operands[1], ports...)
		}
		return value.RemoveExposure(operands[1], ports...)
	})
}

func exposureCommand(args []string) error {
	if len(args) < 1 || args[0] != "list" || len(args) > 2 ||
		(len(args) == 2 && args[1] != "--json") {
		return errors.New("usage: nftfw exposure list [--json]")
	}
	value, _, err := loadManagedIntent()
	if err != nil {
		return err
	}
	result := map[string]any{"tcp": value.PublicTCP, "udp": value.PublicUDP}
	if has(args, "--json") {
		return printJSONOr(result, true)
	}
	fmt.Printf("Public VPN exposure\nTCP: %s\nUDP: %s\n", displayPorts(value.PublicTCP), displayPorts(value.PublicUDP))
	return nil
}

func managedConfigShow(args []string) error {
	if len(args) < 1 || len(args) > 2 || args[0] != "--effective" ||
		(len(args) == 2 && args[1] != "--json") {
		return errors.New("usage: nftfw config show --effective [--json]")
	}
	value, _, err := loadManagedIntent()
	if err != nil {
		return errors.New("CONFIG_NOT_MANAGED")
	}
	generated, err := value.Config()
	if err != nil {
		return err
	}
	result := map[string]any{
		"schema": "nftfw.effective-managed-config.v1", "managed": true,
		"uplink": value.Uplink, "vpn_interface": value.VPNInterface,
		"lan_networks": value.LANNetworks, "management_tcp": value.ManagementTCP,
		"lan_allow_tcp": value.LANAllowTCP, "lan_allow_udp": value.LANAllowUDP,
		"public_tcp": value.PublicTCP, "public_udp": value.PublicUDP,
		"ipv6_mode": "disabled", "resolver_mode": value.ResolverMode,
		"docker_enabled":  value.DockerEnabled,
		"docker_networks": dockerNetworkNames(value.DockerNetworks),
		"zone_count":      len(generated.Zones), "policy_count": len(generated.Policies),
	}
	if has(args, "--json") {
		return printJSONOr(result, true)
	}
	fmt.Println("Mode: managed")
	fmt.Printf("Uplink: %s\nVPN interface: %s\n", value.Uplink, value.VPNInterface)
	fmt.Printf("LAN networks: %s\n", strings.Join(value.LANNetworks, ", "))
	fmt.Printf("LAN management TCP: %s\n", displayPorts(value.ManagementTCP))
	fmt.Printf("LAN allow TCP: %s\nLAN allow UDP: %s\n",
		displayPorts(value.LANAllowTCP), displayPorts(value.LANAllowUDP))
	fmt.Printf("Public TCP: %s\nPublic UDP: %s\n",
		displayPorts(value.PublicTCP), displayPorts(value.PublicUDP))
	fmt.Printf("IPv6: disabled\nResolver: %s\nDocker integration: %t\n",
		value.ResolverMode, value.DockerEnabled)
	if value.DockerEnabled {
		fmt.Printf("Docker networks: %s\nIPv4 forwarding owner: NFTFW\n",
			strings.Join(dockerNetworkNames(value.DockerNetworks), ", "))
	}
	fmt.Printf("Generated policy: %d zones, %d policies\n", len(generated.Zones), len(generated.Policies))
	return nil
}

func managedBackupCommand(args []string) error {
	if len(args) == 0 || (args[0] != "create" && args[0] != "verify") {
		return errors.New("usage: nftfw backup <create [DIRECTORY]|verify DIRECTORY> [--json]")
	}
	if managedEUID() != 0 {
		return errors.New("BACKUP_REQUIRES_ROOT")
	}
	jsonMode := false
	var paths []string
	for _, arg := range args[1:] {
		if arg == "--json" {
			if jsonMode {
				return errors.New("BACKUP_OPTION_DUPLICATE")
			}
			jsonMode = true
		} else {
			paths = append(paths, arg)
		}
	}
	switch args[0] {
	case "create":
		if len(paths) > 1 {
			return errors.New("usage: nftfw backup create [DIRECTORY] [--json]")
		}
		destination := ""
		if len(paths) == 1 {
			destination = paths[0]
		} else {
			destination = filepath.Join(
				filepath.Join(managedStateRoot, "backups"),
				"managed-"+time.Now().UTC().Format("20060102T150405.000000000Z"),
			)
		}
		release, err := acquireSetupLock()
		if err != nil {
			return err
		}
		defer release()
		creator := operatorbackup.Creator{
			Paths: operatorbackup.Paths{
				Config: managedConfigPath, Intent: managedIntentPath, VPN: managedVPNPath,
				Sysctl:       managedSysctl,
				StateDB:      managedStateDB,
				Ledger:       managedLedger,
				Generations:  managedGenerations,
				Enforcement:  managedEnforcement,
				DockerDaemon: managedDockerDaemon,
				DockerDropIn: managedDockerDropIn,
			},
			LockDir: managedRuntimeRoot,
		}
		manifest, err := creator.Create(context.Background(), destination)
		if err != nil {
			return err
		}
		if jsonMode {
			return printJSONOr(map[string]any{
				"status": "verified", "path": destination, "manifest": manifest,
			}, true)
		}
		fmt.Printf("Managed backup created and verified: %s\n", destination)
		return nil
	case "verify":
		if len(paths) != 1 {
			return errors.New("usage: nftfw backup verify DIRECTORY [--json]")
		}
		manifest, err := operatorbackup.Verify(context.Background(), paths[0])
		if err != nil {
			return err
		}
		if jsonMode {
			return printJSONOr(map[string]any{
				"status": "verified", "path": paths[0], "manifest": manifest,
			}, true)
		}
		fmt.Printf("Managed backup verified: %s (%d files)\n", paths[0], len(manifest.Files))
		return nil
	default:
		return errors.New("usage: nftfw backup <create [DIRECTORY]|verify DIRECTORY> [--json]")
	}
}

func lanCommand(args []string) error {
	if len(args) == 1 && args[0] == "list" || len(args) == 2 && args[0] == "list" && args[1] == "--json" {
		value, _, err := loadManagedIntent()
		if err != nil {
			return err
		}
		result := map[string]any{
			"management_tcp": value.ManagementTCP,
			"allow_tcp":      value.LANAllowTCP, "allow_udp": value.LANAllowUDP,
		}
		if has(args, "--json") {
			return printJSONOr(result, true)
		}
		fmt.Printf("LAN management TCP: %s\nLAN allow TCP: %s\nLAN allow UDP: %s\n",
			displayPorts(value.ManagementTCP), displayPorts(value.LANAllowTCP), displayPorts(value.LANAllowUDP))
		return nil
	}
	operands, options, err := parseManagedMutationArgs(args)
	if err != nil || len(operands) < 3 || (operands[0] != "allow" && operands[0] != "deny") {
		return errors.New("usage: nftfw lan <allow|deny> <tcp|udp> PORTS [--dry-run] [--yes] [--json] | nftfw lan list [--json]")
	}
	ports, err := parsePorts(operands[2:])
	if err != nil {
		return err
	}
	action := "deny LAN " + operands[1]
	if operands[0] == "allow" {
		action = "allow LAN " + operands[1]
	}
	return changeManagedIntent(action, options, func(value *intent.Intent) error {
		if operands[0] == "allow" {
			return value.AddLAN(operands[1], ports...)
		}
		return value.RemoveLAN(operands[1], ports...)
	})
}

type managedMutationOptions struct {
	DryRun bool
	Yes    bool
	JSON   bool
}

func parseManagedMutationArgs(args []string) ([]string, managedMutationOptions, error) {
	var operands []string
	var options managedMutationOptions
	seen := map[string]bool{}
	for _, arg := range args {
		if !strings.HasPrefix(arg, "--") {
			operands = append(operands, arg)
			continue
		}
		if seen[arg] {
			return nil, managedMutationOptions{}, errors.New("MANAGED_OPTION_DUPLICATE")
		}
		seen[arg] = true
		switch arg {
		case "--dry-run":
			options.DryRun = true
		case "--yes":
			options.Yes = true
		case "--json":
			options.JSON = true
		default:
			return nil, managedMutationOptions{}, errors.New("MANAGED_OPTION_UNSUPPORTED")
		}
	}
	return operands, options, nil
}

func changeManagedIntent(action string, options managedMutationOptions, change func(*intent.Intent) error) error {
	if managedEUID() != 0 {
		return errors.New("MANAGED_CHANGE_REQUIRES_ROOT")
	}
	ctx := context.Background()
	release, err := acquireSetupLock()
	if err != nil {
		return err
	}
	defer release()
	if err := recoverManagedChange(ctx, true); err != nil {
		return err
	}
	if _, err := readManagedChangeRecord(); err == nil {
		return errors.New("MANAGED_CHANGE_ALREADY_RUNNING")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	value, oldIntent, err := loadManagedIntent()
	if err != nil {
		return err
	}
	oldConfig, err := readProtectedFile(managedConfigPath, 4<<20)
	if err != nil {
		return err
	}
	if err := change(&value); err != nil {
		return err
	}
	newIntent, err := value.Render()
	if err != nil {
		return err
	}
	config, err := value.Config()
	if err != nil {
		return err
	}
	newConfig, err := intent.RenderConfig(config)
	if err != nil {
		return err
	}
	plan := map[string]any{
		"schema": "nftfw.managed-change-plan.v1", "action": action,
		"public_tcp": value.PublicTCP, "public_udp": value.PublicUDP,
		"lan_management_tcp": value.ManagementTCP,
		"lan_allow_tcp":      value.LANAllowTCP, "lan_allow_udp": value.LANAllowUDP,
		"firewall_apply": "safe", "tunnel_required": true,
	}
	if bytes.Equal(oldIntent, newIntent) && bytes.Equal(oldConfig, newConfig) {
		plan["changed"] = false
		if options.JSON {
			return printJSONOr(plan, true)
		}
		fmt.Println("Managed policy is already in the requested state; no changes were made.")
		return nil
	}
	plan["changed"] = true
	if options.DryRun {
		if options.JSON {
			return printJSONOr(plan, true)
		}
		printManagedChangePlan(plan)
		fmt.Println("No files or firewall rules were changed.")
		return nil
	}
	if !options.Yes {
		if options.JSON {
			return errors.New("MANAGED_CONFIRMATION_REQUIRED_USE_YES")
		}
		printManagedChangePlan(plan)
		confirmed, err := confirmManagedChange()
		if err != nil {
			return err
		}
		if !confirmed {
			return errors.New("MANAGED_CHANGE_CANCELED")
		}
	}
	record, err := prepareManagedChange(action, oldIntent, oldConfig, newIntent, newConfig)
	if err != nil {
		return err
	}
	fail := func(cause error) error {
		recoveryErr := rollbackKnownManagedChange(ctx, &record)
		if recoveryErr != nil {
			return errors.Join(cause, fmt.Errorf("managed change rollback: %w", recoveryErr))
		}
		return cause
	}
	if err := managedsetup.WriteAtomicFile(managedIntentPath, newIntent, 0o640); err != nil {
		return fail(err)
	}
	if err := managedsetup.WriteAtomicFile(managedConfigPath, newConfig, 0o640); err != nil {
		return fail(err)
	}
	if err := verifyManagedChangeFiles(record, true); err != nil {
		return fail(err)
	}
	if err := updateManagedChange(&record, "files_published", 0); err != nil {
		return fail(err)
	}
	response, err := managedAPICall(context.Background(), managedControlSock, api.Request{Op: "apply", Safe: true})
	if err != nil {
		return fail(err)
	}
	encoded, _ := json.Marshal(response.Data)
	var result reconcile.Result
	if json.Unmarshal(encoded, &result) != nil || result.Generation == 0 {
		return fail(errors.New("MANAGED_APPLY_RESPONSE_INVALID"))
	}
	record.Generation = result.Generation
	if err := updateManagedChange(&record, "applied", result.Generation); err != nil {
		return fail(err)
	}
	route, err := loadRoutingConfig()
	if err == nil {
		status, statusErr := managedTunnelStatus(context.Background(), route)
		if statusErr != nil || status["healthy"] != true {
			err = errors.New("MANAGED_TUNNEL_UNHEALTHY")
		}
	}
	if err != nil {
		return fail(err)
	}
	if _, err := managedAPICall(context.Background(), managedControlSock, api.Request{Op: "commit", Generation: result.Generation}); err != nil {
		return fail(err)
	}
	if err := finishManagedChange(&record); err != nil {
		recoveryErr := recoverManagedChange(ctx, false)
		if recoveryErr != nil {
			return errors.Join(err, recoveryErr)
		}
	}
	if options.JSON {
		plan["generation"] = result.Generation
		plan["status"] = "committed"
		return printJSONOr(plan, true)
	}
	fmt.Printf("Managed policy committed as generation %d\n", result.Generation)
	return nil
}

func printManagedChangePlan(plan map[string]any) {
	fmt.Printf("Managed policy change: %s\n", plan["action"])
	fmt.Printf("Public TCP: %s\n", displayPorts(plan["public_tcp"].([]int)))
	fmt.Printf("Public UDP: %s\n", displayPorts(plan["public_udp"].([]int)))
	fmt.Printf("LAN management TCP: %s\n", displayPorts(plan["lan_management_tcp"].([]int)))
	fmt.Printf("LAN allow TCP: %s\n", displayPorts(plan["lan_allow_tcp"].([]int)))
	fmt.Printf("LAN allow UDP: %s\n", displayPorts(plan["lan_allow_udp"].([]int)))
	fmt.Println("Apply mode: safe, validated, then committed")
}

func confirmManagedChange() (bool, error) {
	info, err := os.Stdin.Stat()
	if err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return false, errors.New("MANAGED_CONFIRMATION_REQUIRED_USE_YES")
	}
	fmt.Print("Apply this managed policy change? [y/N] ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return false, errors.New("MANAGED_CONFIRMATION_FAILED")
	}
	line = strings.ToLower(strings.TrimSpace(line))
	return line == "y" || line == "yes", nil
}

func loadManagedIntent() (intent.Intent, []byte, error) {
	data, err := readProtectedFile(managedIntentPath, 1<<20)
	if err != nil {
		return intent.Intent{}, nil, err
	}
	value, err := intent.Decode(data)
	return value, data, err
}

func loadRoutingConfig() (routing.Config, error) {
	value, _, err := loadManagedIntent()
	if err != nil {
		return routing.Config{}, err
	}
	profile, _, err := wgconfig.ReadManaged(managedVPNPath)
	if err != nil {
		return routing.Config{}, errors.New(wgconfig.RedactedError(err))
	}
	if len(value.BootstrapIPv4) == 0 {
		return routing.Config{}, errors.New("TUNNEL_BOOTSTRAP_MISSING")
	}
	prefix, err := netip.ParsePrefix(value.BootstrapIPv4[0])
	if err != nil || prefix.Bits() != 32 {
		return routing.Config{}, errors.New("TUNNEL_BOOTSTRAP_INVALID")
	}
	return routing.Config{
		Interface: value.VPNInterface, Uplink: value.Uplink,
		Fwmark: intent.VPNFwmark, Table: routing.DefaultTable,
		Addresses: profile.Addresses, EndpointAddress: prefix.Addr(),
		DNS: profile.DNS, MTU: profile.MTU, Profile: profile,
		Resolver:   routing.ResolverMode(value.ResolverMode),
		RuntimeDir: filepath.Join(managedRuntimeRoot, "setup"),
	}, nil
}

func existingManagedSetup(ctx context.Context, sourceVPN string) (bool, managedsetup.Summary, error) {
	if _, err := os.Lstat(managedIntentPath); errors.Is(err, os.ErrNotExist) {
		return false, managedsetup.Summary{}, nil
	} else if err != nil {
		return false, managedsetup.Summary{}, errors.New("SETUP_MANAGED_STATE_INSPECTION_FAILED")
	}
	value, _, err := loadManagedIntent()
	if err != nil {
		return false, managedsetup.Summary{}, errors.New("SETUP_EXISTING_MANAGED_STATE_INVALID")
	}
	source, _, err := wgconfig.Read(sourceVPN)
	if err != nil {
		return false, managedsetup.Summary{}, errors.New(wgconfig.RedactedError(err))
	}
	managed, _, err := wgconfig.ReadManaged(managedVPNPath)
	if err != nil {
		return false, managedsetup.Summary{}, errors.New(wgconfig.RedactedError(err))
	}
	sourceData, sourceErr := source.NormalizedWGQuick(value.VPNInterface)
	managedData, managedErr := managed.NormalizedWGQuick(value.VPNInterface)
	if sourceErr != nil || managedErr != nil || len(sourceData) != len(managedData) ||
		subtle.ConstantTimeCompare(sourceData, managedData) != 1 {
		return false, managedsetup.Summary{}, errors.New("SETUP_ALREADY_MANAGED_PROFILE_MISMATCH")
	}
	response, err := managedAPICall(ctx, managedStatusSock, api.Request{Op: "status"})
	if err != nil {
		return false, managedsetup.Summary{}, errors.New("SETUP_ALREADY_MANAGED_RECOVERY_REQUIRED")
	}
	encoded, err := json.Marshal(response.Data)
	if err != nil {
		return false, managedsetup.Summary{}, errors.New("SETUP_ALREADY_MANAGED_RECOVERY_REQUIRED")
	}
	var snapshot health.Snapshot
	if json.Unmarshal(encoded, &snapshot) != nil || !snapshot.Managed || !statusHealthy(snapshot) {
		return false, managedsetup.Summary{}, errors.New("SETUP_ALREADY_MANAGED_RECOVERY_REQUIRED")
	}
	route, err := loadRoutingConfig()
	if err != nil {
		return false, managedsetup.Summary{}, errors.New("SETUP_ALREADY_MANAGED_RECOVERY_REQUIRED")
	}
	tunnel, err := managedTunnelStatus(ctx, route)
	if err != nil || tunnel["healthy"] != true {
		return false, managedsetup.Summary{}, errors.New("SETUP_ALREADY_MANAGED_RECOVERY_REQUIRED")
	}
	dockerMode := "disabled"
	if value.DockerEnabled {
		dockerMode = "enabled"
	}
	return true, managedsetup.Summary{
		Schema: "nftfw.setup-plan.v1", Uplink: value.Uplink,
		VPNInterface: value.VPNInterface, LANNetworks: append([]string(nil), value.LANNetworks...),
		ManagementTCP: append([]int(nil), value.ManagementTCP...),
		PublicTCP:     append([]int(nil), value.PublicTCP...),
		PublicUDP:     append([]int(nil), value.PublicUDP...),
		IPv6Mode:      "disabled", DockerMode: dockerMode,
		DockerNetworks: dockerNetworkNames(value.DockerNetworks),
		ResolverMode:   value.ResolverMode,
	}, nil
}

func readProtectedFile(path string, limit int64) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > limit ||
		info.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("MANAGED_FILE_UNSAFE")
	}
	data := make([]byte, info.Size())
	if _, err := io.ReadFull(file, data); err != nil {
		return nil, errors.New("MANAGED_FILE_READ_FAILED")
	}
	return data, nil
}

func acquireSetupLock() (func(), error) {
	if err := os.MkdirAll(filepath.Dir(setupLockPath), 0o750); err != nil {
		return nil, errors.New("SETUP_LOCK_DIRECTORY_FAILED")
	}
	file, err := os.OpenFile(setupLockPath, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, errors.New("SETUP_LOCK_OPEN_FAILED")
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		return nil, errors.New("SETUP_ALREADY_RUNNING")
	}
	return func() {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
	}, nil
}

func confirmSetup() (bool, error) {
	return confirmPrompt("Apply this managed VPN-only firewall plan? [y/N] ")
}

func confirmPrompt(prompt string) (bool, error) {
	info, err := os.Stdin.Stat()
	if err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return false, errors.New("SETUP_CONFIRMATION_REQUIRED_USE_YES")
	}
	fmt.Print(prompt)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return false, errors.New("SETUP_CONFIRMATION_FAILED")
	}
	line = strings.ToLower(strings.TrimSpace(line))
	return line == "y" || line == "yes", nil
}

func confirmDockerRestart(summary managedsetup.Summary) error {
	if !summary.DockerRestart {
		return nil
	}
	fmt.Printf("Docker must restart once to transfer IPv4 forwarding and firewall ownership to NFTFW.\n")
	fmt.Printf("Managed Docker networks: %s\n", strings.Join(summary.DockerNetworks, ", "))
	confirmed, err := confirmPrompt(
		"Restart Docker now with automatic rollback on failure? [y/N] ",
	)
	if err != nil {
		return err
	}
	if !confirmed {
		return errors.New("SETUP_DOCKER_RESTART_CANCELED")
	}
	return nil
}

func printSetupSummary(summary managedsetup.Summary) {
	fmt.Printf("NFT Firewall V2 managed setup plan\nUplink: %s\nVPN interface: %s\nLAN networks: %s\nManagement TCP: %s\nIPv4 Internet: VPN ONLY\nIPv6: %s\nPublic exposure: NONE\nDocker: %s\n",
		summary.Uplink, summary.VPNInterface, strings.Join(summary.LANNetworks, ", "),
		displayPorts(summary.ManagementTCP), strings.ToUpper(summary.IPv6Mode), summary.DockerMode)
	if summary.SourceModeWarning {
		fmt.Println("Warning: the source VPN file is world-readable; the managed copy will be root-only mode 0600.")
	}
	if summary.DockerMode == "enabled" {
		fmt.Printf("Docker networks: %s\n", strings.Join(summary.DockerNetworks, ", "))
		fmt.Println("Docker IPv4 forwarding: NFTFW OWNED")
		if summary.DockerRestart {
			fmt.Println("Docker restart required: YES")
		}
	}
}

func printProtectedSummary(summary managedsetup.Summary, idempotent bool) {
	fmt.Println("NFT Firewall V2 2.1.0")
	fmt.Println("Status: PROTECTED")
	fmt.Println("VPN: HEALTHY")
	fmt.Println("IPv4 Internet: VPN ONLY")
	fmt.Println("IPv6: DISABLED")
	if summary.DockerMode == "enabled" {
		fmt.Printf("Docker: PROTECTED (%d networks, IPv4 forwarding NFTFW-owned)\n", len(summary.DockerNetworks))
	} else {
		fmt.Println("Docker: DISABLED")
	}
	if len(summary.PublicTCP) == 0 && len(summary.PublicUDP) == 0 {
		fmt.Println("Public exposure: NONE")
	} else {
		fmt.Printf("Public exposure TCP: %s\n", displayPorts(summary.PublicTCP))
		fmt.Printf("Public exposure UDP: %s\n", displayPorts(summary.PublicUDP))
	}
	fmt.Println("LAN management: PRESERVED")
	fmt.Println("Boot protection: READY")
	fmt.Println("Rollback: VERIFIED")
	if idempotent {
		fmt.Println("Changes: NONE (already configured)")
	}
}

func parsePorts(values []string) ([]int, error) {
	seen := map[int]bool{}
	var result []int
	for _, value := range values {
		port, err := strconv.Atoi(value)
		if err != nil || port < 1 || port > 65535 || seen[port] {
			return nil, errors.New("PORT_LIST_INVALID")
		}
		seen[port] = true
		result = append(result, port)
	}
	return result, nil
}

func displayPorts(values []int) string {
	if len(values) == 0 {
		return "none"
	}
	parts := make([]string, len(values))
	for i, value := range values {
		parts[i] = strconv.Itoa(value)
	}
	return strings.Join(parts, ",")
}

func dockerNetworkNames(networks []config.DockerNetwork) []string {
	result := make([]string, len(networks))
	for index, network := range networks {
		result[index] = network.Name
	}
	sort.Strings(result)
	return result
}
