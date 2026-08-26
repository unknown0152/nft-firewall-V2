package routing

import (
	"context"
	"encoding/base64"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/unknown0152/nft-firewall-v2/internal/wgconfig"
)

type fakeRunner struct {
	commands []string
	failAt   string
}

func (f *fakeRunner) Run(_ context.Context, input []byte, name string, args ...string) ([]byte, error) {
	command := name + " " + strings.Join(args, " ")
	if len(input) > 0 {
		command += " <stdin>"
	}
	f.commands = append(f.commands, command)
	if strings.Contains(command, f.failAt) && f.failAt != "" {
		return nil, errors.New("injected")
	}
	if command == "ip link show dev nftfw0" {
		return nil, errors.New("absent")
	}
	if strings.Contains(command, "latest-handshakes") {
		return []byte("peer 1\n"), nil
	}
	if command == "ip -j -4 rule show" {
		return []byte("[]"), nil
	}
	if command == "ip -j -4 route show table 51820" {
		return []byte("[]"), nil
	}
	if command == "ip -j -d link show" {
		return []byte("[]"), nil
	}
	return nil, nil
}

func routeKey(fill byte) string {
	value := make([]byte, 32)
	for i := range value {
		value[i] = fill
	}
	return base64.StdEncoding.EncodeToString(value)
}

func routeConfig(t testing.TB) Config {
	t.Helper()
	profile, _, err := wgconfig.Parse([]byte(`[Interface]
PrivateKey = ` + routeKey(1) + `
Address = 10.8.0.2/32
DNS = 1.1.1.1
[Peer]
PublicKey = ` + routeKey(2) + `
AllowedIPs = 0.0.0.0/0
Endpoint = vpn.example.test:51820
`))
	if err != nil {
		t.Fatal(err)
	}
	return Config{
		Interface: "nftfw0", Uplink: "eth0", Fwmark: "0xca6c", Table: DefaultTable,
		Addresses: profile.Addresses, EndpointAddress: netip.MustParseAddr("198.51.100.8"),
		DNS: profile.DNS, MTU: 1420, Profile: profile, Resolver: ResolverResolvconf,
		RuntimeDir: t.TempDir(),
	}
}

func TestUpOwnsInterfaceRoutesRulesAndDNS(t *testing.T) {
	runner := &fakeRunner{}
	manager := Manager{Runner: runner}
	if err := manager.Up(context.Background(), routeConfig(t)); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(runner.commands, "\n")
	for _, want := range []string{
		"ip link add dev nftfw0 type wireguard",
		"wg setconf nftfw0",
		"ip -4 address replace 10.8.0.2/32 dev nftfw0",
		"wg set nftfw0 fwmark 0xca6c",
		"ip -4 route replace default dev nftfw0 table 51820",
		"ip -4 rule add pref 32764 table main suppress_prefixlength 0",
		"ip -4 rule add pref 32765 not fwmark 0xca6c table 51820",
		"resolvconf -a nftfw0 -m 0 -x <stdin>",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing command %q:\n%s", want, joined)
		}
	}
}

func TestFailureRunsRollback(t *testing.T) {
	runner := &fakeRunner{failAt: "route replace"}
	manager := Manager{Runner: runner}
	if err := manager.Up(context.Background(), routeConfig(t)); err == nil {
		t.Fatal("injected route failure was ignored")
	}
	joined := strings.Join(runner.commands, "\n")
	if !strings.Contains(joined, "ip link delete dev nftfw0") ||
		!strings.Contains(joined, "resolvconf -d nftfw0 -f") {
		t.Fatalf("failure did not roll back:\n%s", joined)
	}
}

func TestDeleteRulesRemovesOnlyExactManagedRules(t *testing.T) {
	runner := &fakeRunner{}
	manager := Manager{Runner: runner}
	config := routeConfig(t)
	if err := manager.deleteRules(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(runner.commands, "\n")
	for _, want := range []string{
		"ip -4 rule del pref 32765 not fwmark 0xca6c table 51820",
		"ip -4 rule del pref 32764 table main suppress_prefixlength 0",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing exact deletion %q:\n%s", want, joined)
		}
	}
}

func TestDeleteRulesPreservesForeignSamePriorityRule(t *testing.T) {
	runner := runnerFunc(func(_ context.Context, _ []byte, name string, args ...string) ([]byte, error) {
		if name == "ip" && strings.Join(args, " ") == "-j -4 rule show" {
			return []byte(`[{"priority":32765,"table":100},{"priority":32764,"table":"main"}]`), nil
		}
		return nil, nil
	})
	if err := (Manager{Runner: runner}).deleteRules(context.Background(), routeConfig(t)); err != nil {
		t.Fatalf("foreign rule at a reused priority was treated as owned: %v", err)
	}
}

func TestDeleteRulesRejectsRemainingManagedRule(t *testing.T) {
	runner := runnerFunc(func(_ context.Context, _ []byte, name string, args ...string) ([]byte, error) {
		if name == "ip" && strings.Join(args, " ") == "-j -4 rule show" {
			return []byte(`[{"priority":32765,"not":true,"fwmark":"0xca6c","table":51820}]`), nil
		}
		return nil, nil
	})
	if err := (Manager{Runner: runner}).deleteRules(context.Background(), routeConfig(t)); err == nil ||
		err.Error() != "TUNNEL_RULE_DELETE_FAILED" {
		t.Fatalf("remaining managed rule was not detected: %v", err)
	}
}

func TestUpRefusesForeignRulePriorityBeforeMutation(t *testing.T) {
	var commands []string
	runner := runnerFunc(func(_ context.Context, _ []byte, name string, args ...string) ([]byte, error) {
		command := name + " " + strings.Join(args, " ")
		commands = append(commands, command)
		if command == "ip -j -4 rule show" {
			return []byte(`[{"priority":32765,"table":100}]`), nil
		}
		return []byte("[]"), nil
	})
	err := (Manager{Runner: runner}).Up(context.Background(), routeConfig(t))
	if err == nil || err.Error() != "TUNNEL_RULE_PRIORITY_CONFLICT" {
		t.Fatalf("foreign rule priority was not refused: %v", err)
	}
	if strings.Contains(strings.Join(commands, "\n"), "ip link add") {
		t.Fatalf("routing mutation occurred before conflict refusal: %v", commands)
	}
}

func TestUpRefusesForeignRouteTableBeforeMutation(t *testing.T) {
	var commands []string
	runner := runnerFunc(func(_ context.Context, _ []byte, name string, args ...string) ([]byte, error) {
		command := name + " " + strings.Join(args, " ")
		commands = append(commands, command)
		switch command {
		case "ip -j -4 rule show":
			return []byte("[]"), nil
		case "ip -j -4 route show table 51820":
			return []byte(`[{"dst":"default","dev":"foreign0"}]`), nil
		default:
			return nil, nil
		}
	})
	err := (Manager{Runner: runner}).Up(context.Background(), routeConfig(t))
	if err == nil || err.Error() != "TUNNEL_ROUTE_TABLE_CONFLICT" {
		t.Fatalf("foreign route table was not refused: %v", err)
	}
	if strings.Contains(strings.Join(commands, "\n"), "ip link add") {
		t.Fatalf("routing mutation occurred before conflict refusal: %v", commands)
	}
}

func TestPreflightCleanRejectsReservedIdentityBeforeMutation(t *testing.T) {
	tests := map[string]runnerFunc{
		"rule": func(_ context.Context, _ []byte, name string, args ...string) ([]byte, error) {
			switch name + " " + strings.Join(args, " ") {
			case "ip -j -4 rule show":
				return []byte(`[{"priority":32765,"table":100}]`), nil
			default:
				return []byte("[]"), nil
			}
		},
		"route": func(_ context.Context, _ []byte, name string, args ...string) ([]byte, error) {
			switch name + " " + strings.Join(args, " ") {
			case "ip -j -4 rule show":
				return []byte("[]"), nil
			case "ip -j -4 route show table 51820":
				return []byte(`[{"dst":"default","dev":"foreign0"}]`), nil
			default:
				return []byte("[]"), nil
			}
		},
		"link": func(_ context.Context, _ []byte, name string, args ...string) ([]byte, error) {
			switch name + " " + strings.Join(args, " ") {
			case "ip -j -4 rule show", "ip -j -4 route show table 51820":
				return []byte("[]"), nil
			case "ip -j -d link show":
				return []byte(`[{"ifname":"nftfw0"}]`), nil
			default:
				return []byte("[]"), nil
			}
		},
	}
	for name, runner := range tests {
		t.Run(name, func(t *testing.T) {
			if err := (Manager{Runner: runner}).PreflightClean(context.Background(), routeConfig(t)); err == nil {
				t.Fatal("reserved routing identity was accepted")
			}
		})
	}
}

func TestSecureTemporaryUsesMode0600(t *testing.T) {
	path, err := secureTemporary(t.TempDir(), []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(path)
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("unsafe temporary file: info=%v err=%v", info, err)
	}
}

func TestStatusReportsAbsentHealthyAndStale(t *testing.T) {
	config := routeConfig(t)
	cases := []struct {
		name    string
		output  []byte
		runErr  error
		active  bool
		healthy bool
	}{
		{name: "absent", runErr: errors.New("missing")},
		{
			name:   "healthy",
			output: []byte("peer " + strconv.FormatInt(time.Now().Unix(), 10) + "\n"),
			active: true, healthy: true,
		},
		{
			name:   "stale",
			output: []byte("peer " + strconv.FormatInt(time.Now().Add(-10*time.Minute).Unix(), 10) + "\n"),
			active: true,
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			runner := runnerFunc(func(context.Context, []byte, string, ...string) ([]byte, error) {
				return test.output, test.runErr
			})
			status, err := (Manager{Runner: runner}).Status(context.Background(), config)
			if err != nil {
				t.Fatal(err)
			}
			if status["active"] != test.active || status["healthy"] != test.healthy {
				t.Fatalf("unexpected status: %#v", status)
			}
		})
	}
	malformed := runnerFunc(func(context.Context, []byte, string, ...string) ([]byte, error) {
		return []byte("invalid\npeer not-a-number\n"), nil
	})
	status, err := (Manager{Runner: malformed}).Status(context.Background(), config)
	if err != nil || status["active"] != true || status["healthy"] != false {
		t.Fatalf("malformed handshake output was not bounded: %#v %v", status, err)
	}
}

func TestDetectResolverModes(t *testing.T) {
	if mode, err := DetectResolver(context.Background(), nil, false); err != nil || mode != ResolverNone {
		t.Fatalf("no-DNS resolver detection failed: mode=%s err=%v", mode, err)
	}
	resolvectl := runnerFunc(func(_ context.Context, _ []byte, name string, _ ...string) ([]byte, error) {
		if name == "resolvectl" {
			return nil, nil
		}
		return nil, errors.New("missing")
	})
	if mode, err := DetectResolver(context.Background(), resolvectl, true); err != nil || mode != ResolverResolvectl {
		t.Fatalf("resolvectl detection failed: mode=%s err=%v", mode, err)
	}
	resolvconf := runnerFunc(func(_ context.Context, _ []byte, name string, _ ...string) ([]byte, error) {
		if name == "resolvconf" {
			return nil, nil
		}
		return nil, errors.New("missing")
	})
	if mode, err := DetectResolver(context.Background(), resolvconf, true); err != nil || mode != ResolverResolvconf {
		t.Fatalf("resolvconf detection failed: mode=%s err=%v", mode, err)
	}
	missing := runnerFunc(func(context.Context, []byte, string, ...string) ([]byte, error) {
		return nil, errors.New("missing")
	})
	if _, err := DetectResolver(context.Background(), missing, true); err == nil {
		t.Fatal("unsupported resolver state was accepted")
	}
	// Exercise the production runner selection without asserting host resolver
	// availability; either supported mode or the bounded unsupported error is valid.
	_, _ = DetectResolver(context.Background(), nil, true)
}

func TestConfigValidationRejectsUnsafeInputs(t *testing.T) {
	base := routeConfig(t)
	mutations := []func(*Config){
		func(c *Config) { c.Interface = "" },
		func(c *Config) { c.Uplink = c.Interface },
		func(c *Config) { c.Table = 0 },
		func(c *Config) { c.Fwmark = "invalid" },
		func(c *Config) { c.EndpointAddress = netip.IPv6Unspecified() },
		func(c *Config) { c.Addresses = nil },
		func(c *Config) { c.Addresses = []netip.Prefix{netip.MustParsePrefix("::1/128")} },
		func(c *Config) { c.DNS = []netip.Addr{netip.IPv6Loopback()} },
		func(c *Config) { c.Resolver = ResolverNone },
		func(c *Config) { c.Resolver = ResolverMode("unknown") },
		func(c *Config) { c.RuntimeDir = "" },
	}
	for index, mutate := range mutations {
		candidate := base
		mutate(&candidate)
		if err := candidate.Validate(); err == nil {
			t.Fatalf("unsafe config mutation %d accepted: %#v", index, candidate)
		}
	}
}

func TestResolvectlConfigureAndClear(t *testing.T) {
	runner := &fakeRunner{}
	config := routeConfig(t)
	config.Resolver = ResolverResolvectl
	manager := Manager{Runner: runner}
	if err := manager.configureDNS(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	if err := manager.clearDNS(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(runner.commands, "\n")
	for _, want := range []string{
		"resolvectl dns nftfw0 1.1.1.1",
		"resolvectl domain nftfw0 ~.",
		"resolvectl default-route nftfw0 yes",
		"resolvectl revert nftfw0",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing resolver command %q:\n%s", want, joined)
		}
	}
}

func TestDownIsIdempotentWhenLinkIsAbsent(t *testing.T) {
	runner := &fakeRunner{}
	if err := (Manager{Runner: runner}).Down(context.Background(), routeConfig(t)); err != nil {
		t.Fatal(err)
	}
}

func TestBoundedBufferRejectsOversizedOutput(t *testing.T) {
	var buffer boundedBuffer
	if _, err := buffer.Write(make([]byte, DefaultCommandOutput+1)); err == nil {
		t.Fatal("oversized command output accepted")
	}
	if _, err := buffer.Write([]byte("ok")); err != nil || string(buffer.Bytes()) != "ok" {
		t.Fatalf("bounded buffer failed normal write: %v", err)
	}
}

func TestExecRunnerSuccessInputAndFailure(t *testing.T) {
	output, err := (ExecRunner{}).Run(context.Background(), []byte("hello"), "sh", "-c", "cat")
	if err != nil || string(output) != "hello" {
		t.Fatalf("exec runner input failed: output=%q err=%v", output, err)
	}
	if _, err := (ExecRunner{}).Run(context.Background(), nil, "sh", "-c", "exit 1"); err == nil {
		t.Fatal("exec runner command failure was ignored")
	}
}

func TestPreflightCleanFailureBoundaries(t *testing.T) {
	config := routeConfig(t)
	invalid := config
	invalid.Interface = ""
	if err := (Manager{}).PreflightClean(context.Background(), invalid); err == nil {
		t.Fatal("invalid routing config accepted")
	}
	tests := []struct {
		name   string
		runner runnerFunc
	}{
		{
			name: "rule-json",
			runner: func(_ context.Context, _ []byte, name string, args ...string) ([]byte, error) {
				if name+" "+strings.Join(args, " ") == "ip -j -4 rule show" {
					return []byte("{"), nil
				}
				return []byte("[]"), nil
			},
		},
		{
			name: "route-command",
			runner: func(_ context.Context, _ []byte, name string, args ...string) ([]byte, error) {
				command := name + " " + strings.Join(args, " ")
				if command == "ip -j -4 rule show" {
					return []byte("[]"), nil
				}
				if command == "ip -j -4 route show table 51820" {
					return nil, errors.New("failed")
				}
				return []byte("[]"), nil
			},
		},
		{
			name: "link-json",
			runner: func(_ context.Context, _ []byte, name string, args ...string) ([]byte, error) {
				command := name + " " + strings.Join(args, " ")
				if command == "ip -j -d link show" {
					return []byte("{"), nil
				}
				return []byte("[]"), nil
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := (Manager{Runner: test.runner}).PreflightClean(context.Background(), config); err == nil {
				t.Fatal("invalid preflight response accepted")
			}
		})
	}
}

func TestUpFailureBoundariesRollback(t *testing.T) {
	for _, failAt := range []string{
		"wg setconf", "address replace", "mtu", "wg set nftfw0 fwmark",
		"link set dev nftfw0 up", "rule add pref 32764", "rule add pref 32765",
		"resolvconf -a",
	} {
		t.Run(failAt, func(t *testing.T) {
			runner := &fakeRunner{failAt: failAt}
			if err := (Manager{Runner: runner}).Up(context.Background(), routeConfig(t)); err == nil {
				t.Fatal("injected tunnel-up failure was ignored")
			}
			if !strings.Contains(strings.Join(runner.commands, "\n"), "ip link delete dev nftfw0") {
				t.Fatalf("tunnel-up failure did not clean up link: %v", runner.commands)
			}
		})
	}
}

func TestUpReusesExistingInterfaceWithoutCreatingIt(t *testing.T) {
	var commands []string
	runner := runnerFunc(func(_ context.Context, _ []byte, name string, args ...string) ([]byte, error) {
		command := name + " " + strings.Join(args, " ")
		commands = append(commands, command)
		switch command {
		case "ip -j -4 rule show", "ip -j -4 route show table 51820", "ip -j -d link show":
			return []byte("[]"), nil
		case "ip link show dev nftfw0":
			return nil, nil
		default:
			return nil, nil
		}
	})
	config := routeConfig(t)
	config.DNS = nil
	config.Resolver = ResolverNone
	if err := (Manager{Runner: runner}).Up(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(commands, "\n"), "ip link add dev nftfw0") {
		t.Fatal("existing interface was recreated")
	}
}

func TestDownAggregatesDNSRuleAndLinkFailures(t *testing.T) {
	runner := runnerFunc(func(_ context.Context, _ []byte, name string, args ...string) ([]byte, error) {
		command := name + " " + strings.Join(args, " ")
		switch command {
		case "resolvconf -d nftfw0 -f":
			return nil, errors.New("dns")
		case "ip -j -4 rule show":
			return nil, errors.New("rules")
		case "ip link delete dev nftfw0":
			return nil, errors.New("delete")
		case "ip link show dev nftfw0":
			return nil, nil
		default:
			return nil, nil
		}
	})
	err := (Manager{Runner: runner}).Down(context.Background(), routeConfig(t))
	if err == nil {
		t.Fatal("teardown failures were hidden")
	}
	for _, want := range []string{
		"TUNNEL_DNS_ROLLBACK_FAILED",
		"TUNNEL_RULE_VERIFY_FAILED",
		"TUNNEL_LINK_DELETE_FAILED",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("teardown error missing %s: %v", want, err)
		}
	}
	if err := (Manager{Runner: runner}).Down(context.Background(), Config{}); err == nil {
		t.Fatal("invalid down config accepted")
	}
}

func TestDNSConfigurationFailureBoundaries(t *testing.T) {
	for _, failAt := range []string{"resolvectl dns", "resolvectl domain", "resolvectl default-route"} {
		t.Run(failAt, func(t *testing.T) {
			runner := &fakeRunner{failAt: failAt}
			config := routeConfig(t)
			config.Resolver = ResolverResolvectl
			if err := (Manager{Runner: runner}).configureDNS(context.Background(), config); err == nil {
				t.Fatal("resolvectl failure was ignored")
			}
		})
	}
	config := routeConfig(t)
	config.DNS = nil
	config.Resolver = ResolverNone
	if err := (Manager{Runner: &fakeRunner{}}).configureDNS(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	config.DNS = []netip.Addr{netip.MustParseAddr("1.1.1.1")}
	config.Resolver = ResolverMode("unknown")
	if err := (Manager{Runner: &fakeRunner{}}).configureDNS(context.Background(), config); err == nil {
		t.Fatal("unknown resolver configuration accepted")
	}
	if err := (Manager{Runner: &fakeRunner{}}).clearDNS(context.Background(), Config{}); err != nil {
		t.Fatal(err)
	}
	config.Resolver = ResolverMode("unknown")
	if err := (Manager{Runner: &fakeRunner{}}).clearDNS(context.Background(), config); err == nil {
		t.Fatal("unknown resolver rollback accepted")
	}
}

func TestRuleHelpersRejectInvalidResponses(t *testing.T) {
	config := routeConfig(t)
	runner := runnerFunc(func(_ context.Context, _ []byte, name string, args ...string) ([]byte, error) {
		if name+" "+strings.Join(args, " ") == "ip -j -4 rule show" {
			return []byte(`[{"priority":32764,"table":"main","suppress_prefixlength":0}]`), nil
		}
		return []byte("[]"), nil
	})
	if err := (Manager{Runner: runner}).ensureRulePrioritiesAvailable(context.Background()); err == nil {
		t.Fatal("occupied managed priority accepted")
	}
	if _, err := decodeRules(nil); err == nil {
		t.Fatal("empty rule output accepted")
	}
	if _, err := tableNumber(0); err == nil {
		t.Fatal("invalid route table accepted")
	}
	config.Fwmark = "bad"
	if err := (Manager{Runner: &fakeRunner{}}).deleteRules(context.Background(), config); err == nil {
		t.Fatal("invalid fwmark accepted during rule deletion")
	}
}

func TestSecureTemporaryRejectsUnsafeDirectory(t *testing.T) {
	if _, err := secureTemporary("relative", []byte("secret")); err == nil {
		t.Fatal("relative runtime directory accepted")
	}
	root := t.TempDir()
	parentFile := filepath.Join(root, "file")
	if err := os.WriteFile(parentFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := secureTemporary(filepath.Join(parentFile, "child"), []byte("secret")); err == nil {
		t.Fatal("file accepted as runtime directory")
	}
}

func TestRemainingRoutingInspectionFailures(t *testing.T) {
	config := routeConfig(t)
	if _, err := (Manager{Runner: &fakeRunner{}}).Status(context.Background(), Config{}); err == nil {
		t.Fatal("status accepted invalid config")
	}
	linkFailure := &fakeRunner{failAt: "ip link add dev nftfw0"}
	if err := (Manager{Runner: linkFailure}).Up(context.Background(), config); err == nil {
		t.Fatal("link creation failure was ignored")
	}
	ruleFailure := runnerFunc(func(context.Context, []byte, string, ...string) ([]byte, error) {
		return nil, errors.New("failed")
	})
	if err := (Manager{Runner: ruleFailure}).ensureRulePrioritiesAvailable(context.Background()); err == nil {
		t.Fatal("rule inspection failure was ignored")
	}
	routeJSONFailure := runnerFunc(func(_ context.Context, _ []byte, name string, args ...string) ([]byte, error) {
		command := name + " " + strings.Join(args, " ")
		if command == "ip -j -4 rule show" {
			return []byte("[]"), nil
		}
		if command == "ip -j -4 route show table 51820" {
			return []byte("{"), nil
		}
		return []byte("[]"), nil
	})
	if err := (Manager{Runner: routeJSONFailure}).checkOwnershipConflicts(context.Background(), config); err == nil {
		t.Fatal("invalid route-table JSON accepted")
	}
	routeCommandFailure := runnerFunc(func(_ context.Context, _ []byte, name string, args ...string) ([]byte, error) {
		command := name + " " + strings.Join(args, " ")
		if command == "ip -j -4 rule show" {
			return []byte("[]"), nil
		}
		if command == "ip -j -4 route show table 51820" {
			return nil, errors.New("failed")
		}
		return []byte("[]"), nil
	})
	if err := (Manager{Runner: routeCommandFailure}).checkOwnershipConflicts(context.Background(), config); err == nil {
		t.Fatal("route-table inspection failure was ignored")
	}
	linkCommandFailure := runnerFunc(func(_ context.Context, _ []byte, name string, args ...string) ([]byte, error) {
		command := name + " " + strings.Join(args, " ")
		switch command {
		case "ip -j -4 rule show", "ip -j -4 route show table 51820":
			return []byte("[]"), nil
		case "ip -j -d link show":
			return nil, errors.New("failed")
		default:
			return []byte("[]"), nil
		}
	})
	if err := (Manager{Runner: linkCommandFailure}).PreflightClean(context.Background(), config); err == nil {
		t.Fatal("link inspection failure was ignored")
	}
	resolvectlFailure := &fakeRunner{failAt: "resolvectl revert"}
	config.Resolver = ResolverResolvectl
	if err := (Manager{Runner: resolvectlFailure}).clearDNS(context.Background(), config); err == nil {
		t.Fatal("resolvectl rollback failure was ignored")
	}
}

type runnerFunc func(context.Context, []byte, string, ...string) ([]byte, error)

func (f runnerFunc) Run(ctx context.Context, input []byte, name string, args ...string) ([]byte, error) {
	return f(ctx, input, name, args...)
}

func BenchmarkValidateConfig(b *testing.B) {
	config := routeConfig(b)
	b.ReportAllocs()
	for b.Loop() {
		if err := config.Validate(); err != nil {
			b.Fatal(err)
		}
	}
}
