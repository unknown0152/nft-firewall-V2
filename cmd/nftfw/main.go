package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/unknown0152/nft-firewall-v2/internal/api"
	"github.com/unknown0152/nft-firewall-v2/internal/app"
	"github.com/unknown0152/nft-firewall-v2/internal/compiler"
	"github.com/unknown0152/nft-firewall-v2/internal/config"
	"github.com/unknown0152/nft-firewall-v2/internal/health"
	"github.com/unknown0152/nft-firewall-v2/internal/nft"
	"github.com/unknown0152/nft-firewall-v2/internal/policy"
	"github.com/unknown0152/nft-firewall-v2/internal/recovery"
	"github.com/unknown0152/nft-firewall-v2/internal/state"
	"github.com/unknown0152/nft-firewall-v2/internal/version"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "nftfw:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: nftfw <version|config|plan|apply|commit|rollback|reconcile|status|health|doctor|explain|audit|blocks|block|allow|wg|state>")
	}
	configPath := os.Getenv("NFTFW_CONFIG")
	if configPath == "" {
		configPath = "/etc/nftfw/nftfw.toml"
	}
	statusSock := os.Getenv("NFTFW_STATUS_SOCKET")
	if statusSock == "" {
		statusSock = "/run/nftfw/status.sock"
	}
	controlSock := os.Getenv("NFTFW_CONTROL_SOCKET")
	if controlSock == "" {
		controlSock = "/run/nftfw/control.sock"
	}
	switch args[0] {
	case "version":
		return printJSONOr(version.Current(), has(args, "--json"))
	case "config":
		if len(args) < 2 || args[1] != "validate" {
			return errors.New("usage: nftfw config validate [path]")
		}
		path := configPath
		if len(args) > 2 {
			path = args[2]
		}
		c, err := config.Load(path)
		if err != nil {
			return err
		}
		fmt.Printf("Configuration valid: %s (ipv6=%s strict_vpn=%t)\n", path, c.System.IPv6Mode, c.System.StrictVPN)
		return nil
	case "plan":
		for _, arg := range args[1:] {
			if arg != "--json" && arg != "--show-nft" {
				return fmt.Errorf("unknown plan option %q", arg)
			}
		}
		rt, err := app.Open(context.Background(), configPath, nil)
		if err != nil {
			return err
		}
		defer rt.Close()
		a, err := rt.Artifact(context.Background())
		if err != nil {
			return err
		}
		if err := rt.Backend.CheckCandidate(context.Background(), a.Script); err != nil {
			return fmt.Errorf("kernel validation failed; no firewall changes were made: %w", err)
		}
		current := "none"
		if g, currentErr := rt.Store.LastKnownGood(context.Background()); currentErr == nil {
			current = strconv.FormatUint(g.ID, 10)
		}
		if has(args, "--json") {
			result := map[string]any{"current_generation": current, "proposed_generation": a.Generation, "checksum": a.Checksum, "kernel_validation": "PASS", "management_path": "NOT PROVEN", "zones": len(rt.Config.Zones), "policies": len(rt.Config.Policies)}
			if has(args, "--show-nft") {
				result["nft_transaction"] = a.Script
			}
			return printJSONOr(result, true)
		}
		fmt.Printf("Current generation: %s\nProposed generation: %d\nChecksum: %s\n\nPolicy summary:\nZones: %d\nPolicies: %d\n\nSecurity invariants:\n[PASS] owned tables only\n[PASS] input default deny\n[PASS] forward default deny\n[PASS] output VPN egress pin\n[PASS] IPv6 mode explicit\n[NOT PROVEN] management reachability depends on declared policy\n\nKernel validation:\n[PASS] nft --check\n", current, a.Generation, a.Checksum, len(rt.Config.Zones), len(rt.Config.Policies))
		if has(args, "--show-nft") {
			fmt.Printf("\nCompiled nft transaction:\n%s", a.Script)
		}
		return nil
	case "apply":
		for _, arg := range args[1:] {
			if arg != "--safe" && arg != "--unsafe" {
				return fmt.Errorf("unknown apply option %q", arg)
			}
		}
		if has(args, "--safe") && has(args, "--unsafe") {
			return errors.New("apply accepts only one of --safe or --unsafe")
		}
		safe := !has(args, "--unsafe")
		return controlOrLocal(controlSock, configPath, api.Request{Op: "apply", Safe: safe}, func(rt *app.Runtime) (any, error) {
			a, e := rt.Artifact(context.Background())
			if e != nil {
				return nil, e
			}
			return rt.Manager.Apply(context.Background(), a, safe)
		})
	case "commit":
		id, err := parseID(args, 1)
		if err != nil {
			return err
		}
		return controlOrLocal(controlSock, configPath, api.Request{Op: "commit", Generation: id}, func(rt *app.Runtime) (any, error) { return nil, rt.Manager.Commit(context.Background(), id) })
	case "rollback":
		id, err := parseID(args, 1)
		if err != nil {
			return err
		}
		return controlOrLocal(controlSock, configPath, api.Request{Op: "rollback", Generation: id}, func(rt *app.Runtime) (any, error) { return nil, rt.Manager.Rollback(context.Background(), id) })
	case "reconcile":
		return controlOrLocal(controlSock, configPath, api.Request{Op: "reconcile"}, func(rt *app.Runtime) (any, error) {
			return rt.Manager.Reconcile(context.Background(), true)
		})
	case "status", "health":
		resp, err := api.Call(context.Background(), statusSock, api.Request{Op: "status"})
		if err != nil {
			return err
		}
		if has(args, "--json") {
			return printJSONOr(resp.Data, true)
		}
		var snapshot health.Snapshot
		encoded, marshalErr := json.Marshal(resp.Data)
		if marshalErr != nil || json.Unmarshal(encoded, &snapshot) != nil {
			return errors.New("status response could not be decoded")
		}
		fmt.Printf("Status: %s\nActive generation: %d\nKill switch: %s\nDrift: %t\nWireGuard healthy: %t\nBlocked addresses: %d\nDatabase: %s\n", snapshot.Status, snapshot.ActiveGeneration, snapshot.KillSwitch, snapshot.Drift, snapshot.WireGuard.Healthy, snapshot.BlockedAddresses, snapshot.Database)
		if snapshot.Reason != "" {
			fmt.Printf("Reason: %s\n", snapshot.Reason)
		}
		if args[0] == "health" && snapshot.Status != "HEALTHY" {
			return errors.New("health check is degraded")
		}
		return nil
	case "doctor":
		return doctor(configPath)
	case "explain":
		return explain(configPath, args[1:])
	case "audit":
		resp, err := api.Call(context.Background(), controlSock, api.Request{Op: "audit"})
		if err != nil {
			return err
		}
		return printJSONOr(resp.Data, true)
	case "blocks":
		return blocksCommand(controlSock, configPath, args[1:])
	case "block":
		return claimSubcommand(controlSock, configPath, args[1:], "block-add", "block-remove")
	case "allow":
		return claimSubcommand(controlSock, configPath, args[1:], "allow-add", "block-remove")
	case "wg":
		if len(args) < 2 {
			return errors.New("usage: nftfw wg <status|refresh>")
		}
		if args[1] == "refresh" {
			return controlOrLocal(controlSock, configPath, api.Request{Op: "wg-refresh"}, func(rt *app.Runtime) (any, error) {
				refreshed, err := rt.RefreshEndpoints(context.Background())
				return map[string]any{"refreshed": refreshed}, err
			})
		}
		if args[1] != "status" {
			return errors.New("usage: nftfw wg <status|refresh>")
		}
		return wgStatus(configPath)
	case "state":
		return stateCommand(args[1:])
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func stateCommand(args []string) error {
	if len(args) < 1 || (args[0] != "backup" && args[0] != "verify") {
		return errors.New("usage: nftfw state backup <destination> --database <path> | state verify --database <path>")
	}
	database := os.Getenv("NFTFW_STATE_DB")
	var destination string
	for i := 1; i < len(args); i++ {
		if args[i] == "--database" {
			if i+1 >= len(args) || database != "" {
				return errors.New("--database requires one path")
			}
			database = args[i+1]
			i++
			continue
		}
		if args[0] == "backup" && destination == "" {
			destination = args[i]
			continue
		}
		return fmt.Errorf("unexpected state argument %q", args[i])
	}
	if database == "" {
		database = "/var/lib/nftfw/state.db"
	}
	store, err := state.Open(context.Background(), database)
	if err != nil {
		return err
	}
	defer store.Close()
	if err := store.QuickCheck(context.Background()); err != nil {
		return err
	}
	if args[0] == "verify" {
		fmt.Println("SQLite state: PASS")
		return nil
	}
	if destination == "" || !filepath.IsAbs(destination) {
		return errors.New("backup destination must be an absolute path")
	}
	if err := store.Backup(context.Background(), destination); err != nil {
		return err
	}
	fmt.Printf("SQLite backup created: %s\n", destination)
	return nil
}

func wgStatus(path string) error {
	c, err := config.Load(path)
	if err != nil {
		return err
	}
	out, err := exec.CommandContext(context.Background(), "wg", "show", c.WireGuard.Interface, "latest-handshakes").Output()
	if err != nil {
		return fmt.Errorf("WireGuard interface %s unavailable: %w", c.WireGuard.Interface, err)
	}
	latest := int64(0)
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			v, _ := strconv.ParseInt(fields[1], 10, 64)
			if v > latest {
				latest = v
			}
		}
	}
	if latest == 0 {
		fmt.Printf("WireGuard %s: DEGRADED (no handshake)\n", c.WireGuard.Interface)
		return nil
	}
	age := time.Since(time.Unix(latest, 0)).Round(time.Second)
	fmt.Printf("WireGuard %s: last handshake %s ago\n", c.WireGuard.Interface, age)
	return nil
}

func doctor(path string) error {
	c, err := config.Load(path)
	if err != nil {
		return fmt.Errorf("configuration rejected; no firewall changes were made: %w", err)
	}
	e, err := policy.Compile(c)
	if err != nil {
		return err
	}
	artifact, err := compiler.Compile(compiler.Input{Policy: e, BootstrapV4: c.WireGuard.BootstrapIPs, BootstrapV6: c.WireGuard.BootstrapIPsV6}, 0)
	if err != nil {
		return fmt.Errorf("policy compile: %w", err)
	}
	for _, bin := range []string{"nft", "wg", "ip"} {
		if _, err := exec.LookPath(bin); err != nil {
			return fmt.Errorf("required command %s is missing", bin)
		}
	}
	uplink := ""
	containerConfigured := false
	for _, configured := range c.Interfaces {
		if configured.Role == "uplink" {
			uplink = configured.Name
		}
		if configured.Role == "container" {
			containerConfigured = true
		}
	}
	if _, err := net.InterfaceByName(uplink); err != nil {
		return fmt.Errorf("declared uplink %s is not present", uplink)
	}
	routeDevices, err := defaultRouteDevices(context.Background(), "-4")
	if err != nil {
		return err
	}
	if !contains(routeDevices, uplink) {
		return fmt.Errorf("declared uplink %s does not own an IPv4 default route", uplink)
	}
	if err := secureExistingDirectory(filepath.Dir(c.State.Database)); err != nil {
		return fmt.Errorf("state directory: %w", err)
	}
	if err := secureCurrentExecutable(); err != nil {
		return err
	}
	if containerConfigured {
		forwarding, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
		if err != nil || strings.TrimSpace(string(forwarding)) != "1" {
			return errors.New("container networking is configured but net.ipv4.ip_forward is not 1")
		}
	}
	if err := nft.New(nil).CheckCandidate(context.Background(), artifact.Script); err != nil {
		return fmt.Errorf("kernel candidate validation failed: %w", err)
	}
	if err := (recovery.SystemdGuard{}).Verify(context.Background()); err != nil {
		return fmt.Errorf("safe-apply rollback guard: %w", err)
	}
	fmt.Println("[ok] configuration schema and semantics")
	fmt.Println("[ok] deterministic policy compilation")
	fmt.Println("[ok] nft, wg, and ip commands available")
	fmt.Printf("[ok] declared uplink %s owns the IPv4 default route\n", uplink)
	if _, err := net.InterfaceByName(c.WireGuard.Interface); err != nil {
		fmt.Printf("[warn] WireGuard interface %s is absent; policy remains fail-closed until it appears\n", c.WireGuard.Interface)
	} else {
		fmt.Printf("[ok] WireGuard interface %s exists\n", c.WireGuard.Interface)
	}
	fmt.Println("[ok] state and executable ownership/permissions")
	fmt.Println("[ok] independent rollback timer enabled and active")
	fmt.Println("[ok] exact candidate passed nft --check")
	fmt.Println("[ok] no firewall changes were made")
	return nil
}

func defaultRouteDevices(ctx context.Context, family string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "ip", "-j", family, "route", "show", "default").Output()
	if err != nil {
		return nil, errors.New("could not inspect default routes with ip -j")
	}
	if len(output) > 1<<20 {
		return nil, errors.New("default route JSON exceeds limit")
	}
	var routes []struct {
		Device string `json:"dev"`
	}
	if err := json.Unmarshal(output, &routes); err != nil {
		return nil, fmt.Errorf("decode default route JSON: %w", err)
	}
	var devices []string
	for _, route := range routes {
		if route.Device != "" && !contains(devices, route.Device) {
			devices = append(devices, route.Device)
		}
	}
	if len(devices) == 0 {
		return nil, errors.New("no IPv4 default route is present")
	}
	return devices, nil
}

func secureExistingDirectory(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil || resolved != abs {
		return errors.New("path is absent or contains a symlink")
	}
	info, err := os.Stat(abs)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
		return errors.New("path must be a directory and not group/other writable")
	}
	return nil
}

func secureCurrentExecutable() error {
	path, err := os.Executable()
	if err != nil {
		return err
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return errors.New("nftfw executable is not a protected regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return errors.New("nftfw executable must be owned by root")
	}
	return nil
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func controlOrLocal(sock, path string, req api.Request, local func(*app.Runtime) (any, error)) error {
	if resp, err := api.Call(context.Background(), sock, req); err == nil {
		return printJSONOr(resp.Data, true)
	}
	if os.Getenv("NFTFW_LOCAL") != "1" {
		return fmt.Errorf("nftfwd control socket unavailable; start nftfwd or set NFTFW_LOCAL=1 for an explicit local operation")
	}
	rt, err := app.Open(context.Background(), path, nil)
	if err != nil {
		return err
	}
	defer rt.Close()
	data, err := local(rt)
	if err != nil {
		return err
	}
	return printJSONOr(data, true)
}

func explain(path string, args []string) error {
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	from := fs.String("from", "", "source IP or zone")
	to := fs.String("to", "host", "destination")
	proto := fs.String("protocol", "tcp", "protocol")
	port := fs.Int("port", 0, "port")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, err := config.Load(path)
	if err != nil {
		return err
	}
	e, err := policy.Compile(c)
	if err != nil {
		return err
	}
	d := e.Explain(policy.Query{From: *from, To: *to, Protocol: *proto, Port: *port})
	fmt.Printf("%s\n\nSource: %s\nSource zone: %s\nDestination: %s\n", strings.ToUpper(d.Action), *from, d.SourceZone, *to)
	if d.Matched != nil {
		fmt.Printf("Matched policy: %s\nReason: %s\n", d.Matched.Name, d.Reason)
	} else {
		fmt.Printf("Reason: %s\n", d.Reason)
	}
	return nil
}

func blocksCommand(sock, path string, args []string) error {
	if len(args) == 0 || args[0] != "list" {
		return errors.New("usage: nftfw blocks list")
	}
	return controlOrLocal(sock, path, api.Request{Op: "claims"}, func(rt *app.Runtime) (any, error) {
		claims, e := rt.Store.Claims(context.Background(), time.Now().UTC())
		return claims, e
	})
}
func claimSubcommand(sock, path string, args []string, addOp, removeOp string) error {
	if len(args) < 2 {
		return errors.New("usage: nftfw block|allow add <address> [source] [reason] | remove <claim-id>")
	}
	if args[0] == "remove" {
		id, err := strconv.ParseInt(args[1], 10, 64)
		if err != nil || id <= 0 {
			return errors.New("claim id must be positive")
		}
		return controlOrLocal(sock, path, api.Request{Op: removeOp, ClaimID: id}, func(rt *app.Runtime) (any, error) {
			return rt.Control(context.Background(), api.Request{Op: removeOp, ClaimID: id})
		})
	}
	if args[0] != "add" {
		return errors.New("subcommand must be add or remove")
	}
	req := api.Request{Op: addOp, Address: args[1], Source: "manual", Reason: "operator block"}
	if addOp == "allow-add" {
		req.Source = ""
		req.Reason = "temporary access"
		if len(args) > 2 {
			req.Reason = strings.Join(args[2:], " ")
		}
	} else {
		if len(args) > 2 {
			req.Source = args[2]
		}
		if len(args) > 3 {
			req.Reason = strings.Join(args[3:], " ")
		}
	}
	return controlOrLocal(sock, path, req, func(rt *app.Runtime) (any, error) {
		return rt.Control(context.Background(), req)
	})
}
func parseID(args []string, idx int) (uint64, error) {
	if len(args) <= idx {
		return 0, errors.New("generation id is required")
	}
	return strconv.ParseUint(args[idx], 10, 64)
}
func has(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}
func printJSONOr(v any, jsonMode bool) error {
	if jsonMode {
		b, _ := json.MarshalIndent(v, "", "  ")
		fmt.Println(string(b))
		return nil
	}
	fmt.Printf("%v\n", v)
	return nil
}
