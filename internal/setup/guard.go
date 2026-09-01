package setup

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

const resumeGuardTable = "nftfw_setup_resume_guard"

func renderGuard(uplink, vpnInterface, fwmark string, endpointPort int, endpoints []string, lan []string, management []int) ([]byte, error) {
	if uplink == "" || vpnInterface == "" || uplink == vpnInterface || fwmark == "" ||
		endpointPort < 1 || endpointPort > 65535 || len(endpoints) == 0 || len(lan) == 0 {
		return nil, errors.New("SETUP_GUARD_INPUT_INVALID")
	}
	for _, raw := range endpoints {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || !prefix.Addr().Is4() || prefix.Bits() != 32 {
			return nil, errors.New("SETUP_GUARD_ENDPOINT_INVALID")
		}
	}
	for _, raw := range lan {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || !prefix.Addr().Is4() || !prefix.Addr().IsPrivate() {
			return nil, errors.New("SETUP_GUARD_LAN_INVALID")
		}
	}
	for _, port := range management {
		if port < 1 || port > 65535 {
			return nil, errors.New("SETUP_GUARD_PORT_INVALID")
		}
	}
	sort.Strings(endpoints)
	sort.Strings(lan)
	sort.Ints(management)
	var builder strings.Builder
	builder.WriteString("table inet nftfw_setup_guard {\n")
	builder.WriteString("    set endpoints_v4 { type ipv4_addr; flags interval; elements = { " + strings.Join(endpoints, ", ") + " } }\n")
	builder.WriteString("    set lan_v4 { type ipv4_addr; flags interval; elements = { " + strings.Join(lan, ", ") + " } }\n")
	builder.WriteString("    chain input {\n")
	builder.WriteString("        type filter hook input priority -200; policy accept;\n")
	builder.WriteString("        ct state invalid counter drop comment \"nftfw-setup:invalid-input\"\n")
	builder.WriteString("        iifname \"lo\" counter accept comment \"nftfw-setup:loopback-input\"\n")
	builder.WriteString("        ct state established,related counter accept comment \"nftfw-setup:input-reply\"\n")
	builder.WriteString("        iifname " + strconv.Quote(uplink) + " udp sport 67 udp dport 68 counter accept comment \"nftfw-setup:dhcp-reply\"\n")
	if len(management) > 0 {
		ports := make([]string, len(management))
		for i, port := range management {
			ports[i] = strconv.Itoa(port)
		}
		builder.WriteString("        iifname " + strconv.Quote(uplink) + " ip saddr @lan_v4 tcp dport { " + strings.Join(ports, ", ") + " } counter accept comment \"nftfw-setup:lan-management\"\n")
	}
	builder.WriteString("        iifname " + strconv.Quote(vpnInterface) + " counter drop comment \"nftfw-setup:no-public-input\"\n")
	builder.WriteString("        iifname != \"lo\" counter drop comment \"nftfw-setup:input-default-deny\"\n")
	builder.WriteString("    }\n")
	builder.WriteString("    chain output {\n")
	builder.WriteString("        type filter hook output priority -200; policy accept;\n")
	builder.WriteString("        oifname \"lo\" counter accept comment \"nftfw-setup:loopback-output\"\n")
	builder.WriteString("        oifname " + strconv.Quote(uplink) + " ct direction reply ct state established,related counter accept comment \"nftfw-setup:lan-reply\"\n")
	builder.WriteString("        oifname " + strconv.Quote(uplink) + " udp sport 68 udp dport 67 counter accept comment \"nftfw-setup:dhcp-request\"\n")
	builder.WriteString(fmt.Sprintf("        oifname %s meta mark %s ip daddr @endpoints_v4 udp dport %d counter accept comment \"nftfw-setup:wireguard-endpoint\"\n", strconv.Quote(uplink), fwmark, endpointPort))
	builder.WriteString("        oifname != \"lo\" oifname != " + strconv.Quote(vpnInterface) + " counter drop comment \"nftfw-setup:physical-output-deny\"\n")
	builder.WriteString("    }\n")
	builder.WriteString("    chain forward {\n")
	builder.WriteString("        type filter hook forward priority -200; policy accept;\n")
	builder.WriteString("        oifname != " + strconv.Quote(vpnInterface) + " counter drop comment \"nftfw-setup:physical-forward-deny\"\n")
	builder.WriteString("        iifname " + strconv.Quote(vpnInterface) + " counter drop comment \"nftfw-setup:no-public-forward\"\n")
	builder.WriteString("    }\n")
	builder.WriteString("}\n")
	return []byte(builder.String()), nil
}

func renderResumeGuard(setupGuard []byte) ([]byte, error) {
	const header = "table inet nftfw_setup_guard {\n"
	if len(setupGuard) == 0 || len(setupGuard) > 1<<20 ||
		bytes.Count(setupGuard, []byte(header)) != 1 || !bytes.HasPrefix(setupGuard, []byte(header)) ||
		bytes.Contains(setupGuard, []byte(resumeGuardTable)) {
		return nil, errors.New("SETUP_RESUME_GUARD_INVALID")
	}
	replacement := "table inet " + resumeGuardTable + " {\n" +
		"    comment \"nftfw:setup-resume-guard:v1\"\n"
	return bytes.Replace(setupGuard, []byte(header), []byte(replacement), 1), nil
}
