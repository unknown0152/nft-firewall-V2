// Package routing owns the managed WireGuard interface, policy-routing rules,
// and resolver handoff. Firewall enforcement remains in the compiler/backend.
package routing

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/unknown0152/nft-firewall-v2/internal/wgconfig"
)

const (
	DefaultTable         = 51820
	MainRulePriority     = 32764
	VPNRulePriority      = 32765
	DefaultCommandOutput = 1 << 20
)

type Runner interface {
	Run(context.Context, []byte, string, ...string) ([]byte, error)
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, input []byte, name string, args ...string) ([]byte, error) {
	commandCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	command := exec.CommandContext(commandCtx, name, args...)
	if input != nil {
		command.Stdin = bytes.NewReader(input)
	}
	var output boundedBuffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("%s failed", filepath.Base(name))
	}
	return output.Bytes(), nil
}

type ResolverMode string

const (
	ResolverNone       ResolverMode = "none"
	ResolverResolvectl ResolverMode = "resolvectl"
	ResolverResolvconf ResolverMode = "resolvconf"
)

type Config struct {
	Interface       string
	Uplink          string
	Fwmark          string
	Table           int
	Addresses       []netip.Prefix
	EndpointAddress netip.Addr
	DNS             []netip.Addr
	MTU             int
	Profile         wgconfig.Profile
	Resolver        ResolverMode
	RuntimeDir      string
}

type Manager struct {
	Runner Runner
}

// PreflightClean proves that the deterministic managed routing identities are
// unused before setup performs any host mutation.
func (m Manager) PreflightClean(ctx context.Context, config Config) error {
	if m.Runner == nil {
		m.Runner = ExecRunner{}
	}
	if err := config.Validate(); err != nil {
		return err
	}
	rulesOutput, err := m.Runner.Run(ctx, nil, "ip", "-j", "-4", "rule", "show")
	if err != nil {
		return errors.New("TUNNEL_RULE_VERIFY_FAILED")
	}
	rules, err := decodeRules(rulesOutput)
	if err != nil {
		return errors.New("TUNNEL_RULE_VERIFY_FAILED")
	}
	for _, rule := range rules {
		if rule.Priority == MainRulePriority || rule.Priority == VPNRulePriority {
			return errors.New("TUNNEL_RULE_PRIORITY_CONFLICT")
		}
	}
	routesOutput, err := m.Runner.Run(
		ctx, nil, "ip", "-j", "-4", "route", "show", "table", strconv.Itoa(config.Table),
	)
	if err != nil {
		return errors.New("TUNNEL_ROUTE_TABLE_INSPECTION_FAILED")
	}
	var routes []json.RawMessage
	if len(routesOutput) == 0 || len(routesOutput) > DefaultCommandOutput ||
		json.Unmarshal(routesOutput, &routes) != nil {
		return errors.New("TUNNEL_ROUTE_TABLE_INSPECTION_FAILED")
	}
	if len(routes) != 0 {
		return errors.New("TUNNEL_ROUTE_TABLE_CONFLICT")
	}
	linksOutput, err := m.Runner.Run(ctx, nil, "ip", "-j", "-d", "link", "show")
	if err != nil {
		return errors.New("TUNNEL_LINK_INSPECTION_FAILED")
	}
	var links []struct {
		Name string `json:"ifname"`
	}
	if len(linksOutput) == 0 || len(linksOutput) > DefaultCommandOutput ||
		json.Unmarshal(linksOutput, &links) != nil {
		return errors.New("TUNNEL_LINK_INSPECTION_FAILED")
	}
	for _, link := range links {
		if link.Name == config.Interface {
			return errors.New("TUNNEL_INTERFACE_CONFLICT")
		}
	}
	return nil
}

func (m Manager) Up(ctx context.Context, config Config) error {
	if m.Runner == nil {
		m.Runner = ExecRunner{}
	}
	if err := config.Validate(); err != nil {
		return err
	}
	if err := m.checkOwnershipConflicts(ctx, config); err != nil {
		return err
	}
	if _, err := m.Runner.Run(ctx, nil, "ip", "link", "show", "dev", config.Interface); err != nil {
		if _, err := m.Runner.Run(ctx, nil, "ip", "link", "add", "dev", config.Interface, "type", "wireguard"); err != nil {
			return errors.New("TUNNEL_LINK_CREATE_FAILED")
		}
	}
	rollback := true
	defer func() {
		if rollback {
			_ = m.Down(context.Background(), config)
		}
	}()
	setConfig, err := config.Profile.WGSetConfig(config.EndpointAddress)
	if err != nil {
		return err
	}
	temporary, err := secureTemporary(config.RuntimeDir, setConfig)
	if err != nil {
		return err
	}
	defer os.Remove(temporary)
	if _, err := m.Runner.Run(ctx, nil, "wg", "setconf", config.Interface, temporary); err != nil {
		return errors.New("TUNNEL_WIREGUARD_CONFIG_FAILED")
	}
	for _, prefix := range config.Addresses {
		if _, err := m.Runner.Run(ctx, nil, "ip", "-4", "address", "replace", prefix.String(), "dev", config.Interface); err != nil {
			return errors.New("TUNNEL_ADDRESS_FAILED")
		}
	}
	if config.MTU != 0 {
		if _, err := m.Runner.Run(ctx, nil, "ip", "link", "set", "dev", config.Interface, "mtu", strconv.Itoa(config.MTU)); err != nil {
			return errors.New("TUNNEL_MTU_FAILED")
		}
	}
	if _, err := m.Runner.Run(ctx, nil, "wg", "set", config.Interface, "fwmark", config.Fwmark); err != nil {
		return errors.New("TUNNEL_FWMARK_FAILED")
	}
	if _, err := m.Runner.Run(ctx, nil, "ip", "link", "set", "dev", config.Interface, "up"); err != nil {
		return errors.New("TUNNEL_LINK_UP_FAILED")
	}
	if err := m.deleteRules(ctx, config); err != nil {
		return err
	}
	if err := m.ensureRulePrioritiesAvailable(ctx); err != nil {
		return err
	}
	table := strconv.Itoa(config.Table)
	if _, err := m.Runner.Run(ctx, nil, "ip", "-4", "route", "replace", "default", "dev", config.Interface, "table", table); err != nil {
		return errors.New("TUNNEL_ROUTE_FAILED")
	}
	if _, err := m.Runner.Run(ctx, nil, "ip", "-4", "rule", "add", "pref", strconv.Itoa(MainRulePriority), "table", "main", "suppress_prefixlength", "0"); err != nil {
		return errors.New("TUNNEL_MAIN_RULE_FAILED")
	}
	if _, err := m.Runner.Run(ctx, nil, "ip", "-4", "rule", "add", "pref", strconv.Itoa(VPNRulePriority), "not", "fwmark", config.Fwmark, "table", table); err != nil {
		return errors.New("TUNNEL_VPN_RULE_FAILED")
	}
	if err := m.configureDNS(ctx, config); err != nil {
		return err
	}
	rollback = false
	return nil
}

func (m Manager) Down(ctx context.Context, config Config) error {
	if m.Runner == nil {
		m.Runner = ExecRunner{}
	}
	if config.Interface == "" || config.Table < 1 || config.Table > 0x7fffffff {
		return errors.New("TUNNEL_CONFIG_INVALID")
	}
	var failures []string
	if err := m.clearDNS(ctx, config); err != nil {
		failures = append(failures, err.Error())
	}
	if err := m.deleteRules(ctx, config); err != nil {
		failures = append(failures, err.Error())
	}
	_, _ = m.Runner.Run(ctx, nil, "ip", "-4", "route", "flush", "table", strconv.Itoa(config.Table))
	if _, err := m.Runner.Run(ctx, nil, "ip", "link", "delete", "dev", config.Interface); err != nil {
		if _, showErr := m.Runner.Run(ctx, nil, "ip", "link", "show", "dev", config.Interface); showErr == nil {
			failures = append(failures, "TUNNEL_LINK_DELETE_FAILED")
		}
	}
	if len(failures) > 0 {
		sort.Strings(failures)
		return errors.New(strings.Join(failures, ","))
	}
	return nil
}

func (m Manager) Status(ctx context.Context, config Config) (map[string]any, error) {
	if m.Runner == nil {
		m.Runner = ExecRunner{}
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	handshakes, err := m.Runner.Run(ctx, nil, "wg", "show", config.Interface, "latest-handshakes")
	if err != nil {
		return map[string]any{"interface": config.Interface, "active": false, "healthy": false}, nil
	}
	latest := int64(0)
	for _, line := range strings.Split(string(handshakes), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		value, _ := strconv.ParseInt(fields[1], 10, 64)
		if value > latest {
			latest = value
		}
	}
	healthy := latest > 0 && time.Since(time.Unix(latest, 0)) <= 3*time.Minute
	return map[string]any{
		"interface": config.Interface, "active": true, "healthy": healthy,
		"latest_handshake": latest,
	}, nil
}

func (c Config) Validate() error {
	if c.Interface == "" || c.Uplink == "" || c.Interface == c.Uplink ||
		c.Table < 1 || c.Table > 0x7fffffff || c.RuntimeDir == "" {
		return errors.New("TUNNEL_CONFIG_INVALID")
	}
	if c.Fwmark == "" || !c.EndpointAddress.Is4() || c.EndpointAddress.IsUnspecified() ||
		c.EndpointAddress.IsLoopback() || c.EndpointAddress.IsMulticast() || len(c.Addresses) == 0 {
		return errors.New("TUNNEL_CONFIG_INVALID")
	}
	for _, prefix := range c.Addresses {
		if !prefix.Addr().Is4() || prefix.Bits() == 0 {
			return errors.New("TUNNEL_CONFIG_INVALID")
		}
	}
	for _, address := range c.DNS {
		if !address.Is4() || address.IsUnspecified() || address.IsLoopback() || address.IsMulticast() {
			return errors.New("TUNNEL_DNS_INVALID")
		}
	}
	if len(c.DNS) > 0 && c.Resolver != ResolverResolvectl && c.Resolver != ResolverResolvconf {
		return errors.New("TUNNEL_RESOLVER_UNSUPPORTED")
	}
	if c.Resolver != ResolverNone && c.Resolver != ResolverResolvectl && c.Resolver != ResolverResolvconf {
		return errors.New("TUNNEL_RESOLVER_UNSUPPORTED")
	}
	if mark, err := strconv.ParseUint(c.Fwmark, 0, 32); err != nil || mark == 0 {
		return errors.New("TUNNEL_CONFIG_INVALID")
	}
	return nil
}

func DetectResolver(ctx context.Context, runner Runner, hasDNS bool) (ResolverMode, error) {
	if !hasDNS {
		return ResolverNone, nil
	}
	if runner == nil {
		runner = ExecRunner{}
	}
	if _, err := runner.Run(ctx, nil, "resolvectl", "status"); err == nil {
		return ResolverResolvectl, nil
	}
	if _, err := runner.Run(ctx, nil, "resolvconf", "--version"); err == nil {
		return ResolverResolvconf, nil
	}
	return ResolverNone, errors.New("TUNNEL_RESOLVER_UNSUPPORTED")
}

func (m Manager) configureDNS(ctx context.Context, config Config) error {
	if len(config.DNS) == 0 || config.Resolver == ResolverNone {
		return nil
	}
	values := make([]string, len(config.DNS))
	for i, address := range config.DNS {
		values[i] = address.String()
	}
	switch config.Resolver {
	case ResolverResolvectl:
		if _, err := m.Runner.Run(ctx, nil, "resolvectl", append([]string{"dns", config.Interface}, values...)...); err != nil {
			return errors.New("TUNNEL_DNS_CONFIG_FAILED")
		}
		if _, err := m.Runner.Run(ctx, nil, "resolvectl", "domain", config.Interface, "~."); err != nil {
			return errors.New("TUNNEL_DNS_CONFIG_FAILED")
		}
		if _, err := m.Runner.Run(ctx, nil, "resolvectl", "default-route", config.Interface, "yes"); err != nil {
			return errors.New("TUNNEL_DNS_CONFIG_FAILED")
		}
	case ResolverResolvconf:
		var input strings.Builder
		for _, value := range values {
			input.WriteString("nameserver " + value + "\n")
		}
		if _, err := m.Runner.Run(ctx, []byte(input.String()), "resolvconf", "-a", config.Interface, "-m", "0", "-x"); err != nil {
			return errors.New("TUNNEL_DNS_CONFIG_FAILED")
		}
	default:
		return errors.New("TUNNEL_RESOLVER_UNSUPPORTED")
	}
	return nil
}

func (m Manager) clearDNS(ctx context.Context, config Config) error {
	switch config.Resolver {
	case ResolverNone, "":
		return nil
	case ResolverResolvectl:
		if _, err := m.Runner.Run(ctx, nil, "resolvectl", "revert", config.Interface); err != nil {
			return errors.New("TUNNEL_DNS_ROLLBACK_FAILED")
		}
	case ResolverResolvconf:
		if _, err := m.Runner.Run(ctx, nil, "resolvconf", "-d", config.Interface, "-f"); err != nil {
			return errors.New("TUNNEL_DNS_ROLLBACK_FAILED")
		}
	default:
		return errors.New("TUNNEL_RESOLVER_UNSUPPORTED")
	}
	return nil
}

func (m Manager) deleteRules(ctx context.Context, config Config) error {
	tableText := strconv.Itoa(config.Table)
	_, _ = m.Runner.Run(
		ctx, nil, "ip", "-4", "rule", "del", "pref", strconv.Itoa(VPNRulePriority),
		"not", "fwmark", config.Fwmark, "table", tableText,
	)
	_, _ = m.Runner.Run(
		ctx, nil, "ip", "-4", "rule", "del", "pref", strconv.Itoa(MainRulePriority),
		"table", "main", "suppress_prefixlength", "0",
	)
	output, err := m.Runner.Run(ctx, nil, "ip", "-j", "-4", "rule", "show")
	if err != nil {
		return errors.New("TUNNEL_RULE_VERIFY_FAILED")
	}
	rules, err := decodeRules(output)
	if err != nil {
		return errors.New("TUNNEL_RULE_VERIFY_FAILED")
	}
	fwmark, err := strconv.ParseUint(config.Fwmark, 0, 32)
	if err != nil {
		return errors.New("TUNNEL_CONFIG_INVALID")
	}
	tableID, err := tableNumber(config.Table)
	if err != nil {
		return errors.New("TUNNEL_CONFIG_INVALID")
	}
	for _, rule := range rules {
		if rule.isManagedMain() || rule.isManagedVPN(tableID, fwmark) {
			return errors.New("TUNNEL_RULE_DELETE_FAILED")
		}
	}
	return nil
}

func (m Manager) ensureRulePrioritiesAvailable(ctx context.Context) error {
	output, err := m.Runner.Run(ctx, nil, "ip", "-j", "-4", "rule", "show")
	if err != nil {
		return errors.New("TUNNEL_RULE_VERIFY_FAILED")
	}
	rules, err := decodeRules(output)
	if err != nil {
		return errors.New("TUNNEL_RULE_VERIFY_FAILED")
	}
	for _, rule := range rules {
		if rule.Priority == MainRulePriority || rule.Priority == VPNRulePriority {
			return errors.New("TUNNEL_RULE_PRIORITY_CONFLICT")
		}
	}
	return nil
}

func (m Manager) checkOwnershipConflicts(ctx context.Context, config Config) error {
	rulesOutput, err := m.Runner.Run(ctx, nil, "ip", "-j", "-4", "rule", "show")
	if err != nil {
		return errors.New("TUNNEL_RULE_VERIFY_FAILED")
	}
	rules, err := decodeRules(rulesOutput)
	if err != nil {
		return errors.New("TUNNEL_RULE_VERIFY_FAILED")
	}
	mark, _ := strconv.ParseUint(config.Fwmark, 0, 32)
	table, _ := tableNumber(config.Table)
	for _, rule := range rules {
		if rule.Priority != MainRulePriority && rule.Priority != VPNRulePriority {
			continue
		}
		if rule.isManagedMain() || rule.isManagedVPN(table, mark) {
			continue
		}
		return errors.New("TUNNEL_RULE_PRIORITY_CONFLICT")
	}
	routesOutput, err := m.Runner.Run(
		ctx, nil, "ip", "-j", "-4", "route", "show", "table", strconv.Itoa(config.Table),
	)
	if err != nil {
		return errors.New("TUNNEL_ROUTE_TABLE_INSPECTION_FAILED")
	}
	var routes []struct {
		Destination string `json:"dst"`
		Device      string `json:"dev"`
	}
	if len(routesOutput) == 0 || len(routesOutput) > DefaultCommandOutput ||
		json.Unmarshal(routesOutput, &routes) != nil {
		return errors.New("TUNNEL_ROUTE_TABLE_INSPECTION_FAILED")
	}
	for _, route := range routes {
		if (route.Destination == "default" || route.Destination == "0.0.0.0/0") &&
			route.Device == config.Interface {
			continue
		}
		return errors.New("TUNNEL_ROUTE_TABLE_CONFLICT")
	}
	return nil
}

type policyRule struct {
	Priority       int             `json:"priority"`
	Table          json.RawMessage `json:"table"`
	Fwmark         json.RawMessage `json:"fwmark"`
	Not            bool            `json:"not"`
	SuppressPrefix json.RawMessage `json:"suppress_prefixlength"`
}

func decodeRules(data []byte) ([]policyRule, error) {
	if len(data) == 0 || len(data) > DefaultCommandOutput {
		return nil, errors.New("invalid rule output")
	}
	var rules []policyRule
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil, err
	}
	return rules, nil
}

func (r policyRule) isManagedMain() bool {
	return r.Priority == MainRulePriority && rawNumberOrName(r.Table, "main", 254) &&
		rawNumberOrName(r.SuppressPrefix, "", 0) && len(r.Fwmark) == 0
}

func (r policyRule) isManagedVPN(table, fwmark uint64) bool {
	return r.Priority == VPNRulePriority && rawNumberOrName(r.Table, "", table) &&
		rawNumberOrName(r.Fwmark, "", fwmark) && r.Not
}

func tableNumber(table int) (uint64, error) {
	if table < 1 || table > 0x7fffffff {
		return 0, errors.New("invalid route table")
	}
	return strconv.ParseUint(strconv.Itoa(table), 10, 32)
}

func rawNumberOrName(raw json.RawMessage, name string, number uint64) bool {
	if len(raw) == 0 {
		return false
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		if name != "" && text == name {
			return true
		}
		value, err := strconv.ParseUint(text, 0, 64)
		return err == nil && value == number
	}
	var value uint64
	return json.Unmarshal(raw, &value) == nil && value == number
}

func secureTemporary(directory string, data []byte) (string, error) {
	if directory == "" || !filepath.IsAbs(directory) {
		return "", errors.New("TUNNEL_RUNTIME_DIR_INVALID")
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", errors.New("TUNNEL_RUNTIME_DIR_FAILED")
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return "", errors.New("TUNNEL_RUNTIME_DIR_FAILED")
	}
	file, err := os.CreateTemp(directory, ".wg-setconf-*")
	if err != nil {
		return "", errors.New("TUNNEL_SECRET_STAGE_FAILED")
	}
	path := file.Name()
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return "", errors.New("TUNNEL_SECRET_STAGE_FAILED")
	}
	if _, err := file.Write(data); err != nil {
		return "", errors.New("TUNNEL_SECRET_STAGE_FAILED")
	}
	if err := file.Sync(); err != nil {
		return "", errors.New("TUNNEL_SECRET_STAGE_FAILED")
	}
	if err := file.Close(); err != nil {
		return "", errors.New("TUNNEL_SECRET_STAGE_FAILED")
	}
	ok = true
	return path, nil
}

type boundedBuffer struct {
	data []byte
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if len(b.data)+len(p) > DefaultCommandOutput {
		return 0, errors.New("command output limit exceeded")
	}
	b.data = append(b.data, p...)
	return len(p), nil
}

func (b *boundedBuffer) Bytes() []byte {
	return append([]byte(nil), b.data...)
}
