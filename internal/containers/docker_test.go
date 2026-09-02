package containers

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/unknown0152/nft-firewall-v2/internal/config"
)

const (
	dockerIDOne   = "1111111111111111111111111111111111111111111111111111111111111111"
	dockerIDTwo   = "2222222222222222222222222222222222222222222222222222222222222222"
	dockerIDThree = "3333333333333333333333333333333333333333333333333333333333333333"
)

func expectedMediaNetwork() []config.DockerNetwork {
	return []config.DockerNetwork{{
		Name: "media", Driver: "bridge", BridgeInterface: "br-media",
		Subnets:  []string{"172.19.0.0/16", "fd00:19::/64"},
		Gateways: []string{"172.19.0.1", "fd00:19::1"},
	}}
}

func inspectDocument(id, name, driver, bridge, subnetGatewayJSON string) string {
	return fmt.Sprintf(`[{"Id":%q,"Name":%q,"Driver":%q,"Internal":false,"EnableIPv6":true,"Options":{"com.docker.network.bridge.name":%q},"IPAM":{"Config":[%s]}}]`, id, name, driver, bridge, subnetGatewayJSON)
}

func writeDockerFixture(t *testing.T, list, inspect string, inspectExit int) string {
	t.Helper()
	path := filepath.Join(secureTestDir(t), "docker")
	list = strings.ReplaceAll(list, "'", "")
	inspect = strings.ReplaceAll(inspect, "'", "")
	script := fmt.Sprintf(`#!/bin/sh
if [ "$1" != --host ] || [ "$2" != unix:///var/run/docker.sock ]; then
  exit 99
fi
shift 2
if [ "$1" = network ] && [ "$2" = ls ] && [ "$3" = --no-trunc ]; then
  printf '%%s\n' '%s'
  exit 0
fi
if [ "$1" = network ] && [ "$2" = inspect ] && [ "$3" = -- ]; then
  if [ %d -ne 0 ]; then exit %d; fi
  printf '%%s\n' '%s'
  exit 0
fi
exit 98
`, list, inspectExit, inspectExit, inspect)
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func observerWithDockerFixture(
	t *testing.T, list, inspect string, inspectExit int, expected []config.DockerNetwork,
) Observer {
	t.Helper()
	binary := writeDockerFixture(t, list, inspect, inspectExit)
	return Observer{
		DockerBinary: binary,
		Expected:     expected,
		Run: func(ctx context.Context, limit int64, name string, args ...string) ([]byte, error) {
			if name == "ip" {
				return []byte(`[{"ifname":"br-media"}]`), nil
			}
			return boundedOutput(ctx, limit, name, args...)
		},
	}
}

func TestObserverRequiresDockerFirewallOwnershipDisabled(t *testing.T) {
	dir := secureTestDir(t)
	path := filepath.Join(dir, "daemon.json")
	safe := `{"iptables":false,"ip6tables":false,"ip-forward":false,"ip-masq":false,"userland-proxy":false}`
	if err := os.WriteFile(path, []byte(safe), 0o600); err != nil {
		t.Fatal(err)
	}
	o := Observer{DaemonConfig: path}
	ok, _, err := o.FirewallPolicy()
	if err != nil || !ok {
		t.Fatalf("safe Docker configuration rejected: ok=%t err=%v", ok, err)
	}
	unsafe := []string{
		`{"iptables":true,"ip6tables":false,"ip-forward":false,"ip-masq":false,"userland-proxy":false}`,
		`{"iptables":false,"ip6tables":false,"ip-forward":false,"ip-masq":false}`,
	}
	for _, body := range unsafe {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		ok, _, err = o.FirewallPolicy()
		if err != nil || ok {
			t.Fatalf("unsafe Docker ownership accepted: ok=%t err=%v config=%s", ok, err, body)
		}
	}
}

func TestObserverReturnsExactDualStackStableTuple(t *testing.T) {
	list := dockerIDOne + "\tmedia\tbridge"
	inspect := inspectDocument(dockerIDOne, "media", "bridge", "br-media", `{"Subnet":"172.19.0.0/16","Gateway":"172.19.0.1"},{"Subnet":"fd00:19::/64","Gateway":"fd00:19::1"}`)
	o := observerWithDockerFixture(t, list, inspect, 0, expectedMediaNetwork())
	networks, err := o.Networks(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(networks) != 2 || networks[0].ID != dockerIDOne || networks[0].Name != "media" || networks[0].BridgeInterface != "br-media" || networks[0].CIDR != "172.19.0.0/16" || networks[0].Gateway != "172.19.0.1" || networks[1].CIDR != "fd00:19::/64" {
		t.Fatalf("unexpected networks: %#v", networks)
	}
}

func TestObserverAllowsChangedGeneratedIDForSameStableTuple(t *testing.T) {
	list := dockerIDTwo + "\tmedia\tbridge"
	inspect := inspectDocument(dockerIDTwo, "media", "bridge", "br-media", `{"Subnet":"172.19.0.0/16","Gateway":"172.19.0.1"},{"Subnet":"fd00:19::/64","Gateway":"fd00:19::1"}`)
	o := observerWithDockerFixture(t, list, inspect, 0, expectedMediaNetwork())
	networks, err := o.Networks(context.Background())
	if err != nil || len(networks) != 2 || networks[0].ID != dockerIDTwo {
		t.Fatalf("stable recreation rejected: networks=%#v err=%v", networks, err)
	}
}

func TestObserverBatchesAuthorizedNetworkInspectionByImmutableIDs(t *testing.T) {
	expected := []config.DockerNetwork{
		{
			Name: "bridge", Driver: "bridge", BridgeInterface: "docker0",
			Subnets: []string{"172.17.0.0/16"}, Gateways: []string{"172.17.0.1"},
		},
		{
			Name: "media", Driver: "bridge", BridgeInterface: "br-media",
			Subnets: []string{"172.19.0.0/16"}, Gateways: []string{"172.19.0.1"},
		},
	}
	var commands [][]string
	observer := Observer{
		Expected: expected,
		Run: func(_ context.Context, _ int64, name string, args ...string) ([]byte, error) {
			command := append([]string{name}, args...)
			commands = append(commands, command)
			switch {
			case name == "docker" && reflect.DeepEqual(args, []string{
				"--host", localDockerHost, "network", "ls", "--no-trunc",
				"--format", "{{.ID}}\t{{.Name}}\t{{.Driver}}",
			}):
				return []byte(dockerIDOne + "\tbridge\tbridge\n" + dockerIDTwo + "\tmedia\tbridge\n"), nil
			case name == "docker" && reflect.DeepEqual(args, []string{
				"--host", localDockerHost, "network", "inspect", "--", dockerIDOne, dockerIDTwo,
			}):
				return []byte(`[
{"Id":"` + dockerIDTwo + `","Name":"media","Driver":"bridge","Internal":false,"EnableIPv6":false,"Options":{"com.docker.network.bridge.name":"br-media"},"IPAM":{"Config":[{"Subnet":"172.19.0.0/16","Gateway":"172.19.0.1"}]}},
{"Id":"` + dockerIDOne + `","Name":"bridge","Driver":"bridge","Internal":false,"EnableIPv6":false,"Options":{},"IPAM":{"Config":[{"Subnet":"172.17.0.0/16","Gateway":"172.17.0.1"}]}}
]`), nil
			case name == "ip":
				return []byte(`[{"ifname":"present"}]`), nil
			default:
				return nil, fmt.Errorf("unexpected command: %v", command)
			}
		},
	}
	networks, err := observer.Networks(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(networks) != 2 || networks[0].Name != "bridge" || networks[1].Name != "media" {
		t.Fatalf("batched observation lost a network: %#v", networks)
	}
	inspectCalls := 0
	for _, command := range commands {
		if len(command) >= 5 && command[0] == "docker" && command[4] == "inspect" {
			inspectCalls++
		}
	}
	if inspectCalls != 1 {
		t.Fatalf("Docker networks were not inspected in one bounded call: %#v", commands)
	}
}

func TestObserverRejectsIncompleteBatchedNetworkInspection(t *testing.T) {
	expected := []config.DockerNetwork{
		{Name: "bridge", Driver: "bridge", BridgeInterface: "docker0", Subnets: []string{"172.17.0.0/16"}, Gateways: []string{"172.17.0.1"}},
		{Name: "media", Driver: "bridge", BridgeInterface: "br-media", Subnets: []string{"172.19.0.0/16"}, Gateways: []string{"172.19.0.1"}},
	}
	observer := Observer{
		Expected: expected,
		Run: func(_ context.Context, _ int64, name string, args ...string) ([]byte, error) {
			if name == "docker" && len(args) > 3 && args[2] == "network" && args[3] == "ls" {
				return []byte(dockerIDOne + "\tbridge\tbridge\n" + dockerIDTwo + "\tmedia\tbridge\n"), nil
			}
			if name == "docker" {
				return []byte(`[{"Id":"` + dockerIDOne + `","Name":"bridge","Driver":"bridge"}]`), nil
			}
			return nil, errors.New("unexpected command")
		},
	}
	if _, err := observer.Networks(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "expected 2 objects") {
		t.Fatalf("incomplete batched inspection was accepted: %v", err)
	}
}

func TestObserverRejectsDriftAmbiguityAndInspectionRace(t *testing.T) {
	validIPAM := `{"Subnet":"172.19.0.0/16","Gateway":"172.19.0.1"},{"Subnet":"fd00:19::/64","Gateway":"fd00:19::1"}`
	tests := []struct {
		name        string
		list        string
		inspect     string
		inspectExit int
	}{
		{"unsafe name", dockerIDOne + "\t--config=/tmp/evil\tbridge", "[]", 0},
		{"unknown bridge", dockerIDOne + "\tunknown\tbridge", inspectDocument(dockerIDOne, "unknown", "bridge", "br-unknown", validIPAM), 0},
		{"ID changed during inspect", dockerIDOne + "\tmedia\tbridge", inspectDocument(dockerIDTwo, "media", "bridge", "br-media", validIPAM), 0},
		{"name changed during inspect", dockerIDOne + "\tmedia\tbridge", inspectDocument(dockerIDOne, "other", "bridge", "br-media", validIPAM), 0},
		{"driver drift", dockerIDOne + "\tmedia\tbridge", inspectDocument(dockerIDOne, "media", "overlay", "br-media", validIPAM), 0},
		{"bridge option drift", dockerIDOne + "\tmedia\tbridge", inspectDocument(dockerIDOne, "media", "bridge", "br-other", validIPAM), 0},
		{"subnet drift", dockerIDOne + "\tmedia\tbridge", inspectDocument(dockerIDOne, "media", "bridge", "br-media", `{"Subnet":"172.20.0.0/16","Gateway":"172.20.0.1"},{"Subnet":"fd00:19::/64","Gateway":"fd00:19::1"}`), 0},
		{"gateway drift", dockerIDOne + "\tmedia\tbridge", inspectDocument(dockerIDOne, "media", "bridge", "br-media", `{"Subnet":"172.19.0.0/16","Gateway":"172.19.0.2"},{"Subnet":"fd00:19::/64","Gateway":"fd00:19::1"}`), 0},
		{"internal mode", dockerIDOne + "\tmedia\tbridge", strings.Replace(inspectDocument(dockerIDOne, "media", "bridge", "br-media", validIPAM), `"Internal":false`, `"Internal":true`, 1), 0},
		{"IPv6 mode drift", dockerIDOne + "\tmedia\tbridge", strings.Replace(inspectDocument(dockerIDOne, "media", "bridge", "br-media", validIPAM), `"EnableIPv6":true`, `"EnableIPv6":false`, 1), 0},
		{"inspect race", dockerIDOne + "\tmedia\tbridge", "", 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			o := observerWithDockerFixture(
				t, test.list, test.inspect, test.inspectExit, expectedMediaNetwork(),
			)
			if _, err := o.Networks(context.Background()); err == nil {
				t.Fatal("unsafe Docker observation accepted")
			}
		})
	}
}

func TestObserverRejectsMissingAuthorization(t *testing.T) {
	o := Observer{}
	if _, err := o.Networks(context.Background()); err == nil {
		t.Fatal("Docker observation without configured tuples accepted")
	}
}

func BenchmarkObserveManagedDockerNetworksBatched(b *testing.B) {
	expected := []config.DockerNetwork{
		{Name: "bridge", Driver: "bridge", BridgeInterface: "docker0", Subnets: []string{"172.17.0.0/16"}, Gateways: []string{"172.17.0.1"}},
		{Name: "media", Driver: "bridge", BridgeInterface: "br-media", Subnets: []string{"172.19.0.0/16"}, Gateways: []string{"172.19.0.1"}},
		{Name: "apps", Driver: "bridge", BridgeInterface: "br-apps", Subnets: []string{"172.20.0.0/16"}, Gateways: []string{"172.20.0.1"}},
	}
	list := []byte(
		dockerIDOne + "\tbridge\tbridge\n" +
			dockerIDTwo + "\tmedia\tbridge\n" +
			dockerIDThree + "\tapps\tbridge\n",
	)
	inspect := []byte(`[
{"Id":"` + dockerIDThree + `","Name":"apps","Driver":"bridge","Internal":false,"EnableIPv6":false,"Options":{"com.docker.network.bridge.name":"br-apps"},"IPAM":{"Config":[{"Subnet":"172.20.0.0/16","Gateway":"172.20.0.1"}]}},
{"Id":"` + dockerIDOne + `","Name":"bridge","Driver":"bridge","Internal":false,"EnableIPv6":false,"Options":{},"IPAM":{"Config":[{"Subnet":"172.17.0.0/16","Gateway":"172.17.0.1"}]}},
{"Id":"` + dockerIDTwo + `","Name":"media","Driver":"bridge","Internal":false,"EnableIPv6":false,"Options":{"com.docker.network.bridge.name":"br-media"},"IPAM":{"Config":[{"Subnet":"172.19.0.0/16","Gateway":"172.19.0.1"}]}}
]`)
	observer := Observer{
		Expected: expected,
		Run: func(_ context.Context, _ int64, name string, args ...string) ([]byte, error) {
			switch {
			case name == "docker" && len(args) > 3 && args[2] == "network" && args[3] == "ls":
				return list, nil
			case name == "docker" && len(args) > 3 && args[2] == "network" && args[3] == "inspect":
				return inspect, nil
			case name == "ip":
				return []byte(`[{"ifname":"present"}]`), nil
			default:
				return nil, fmt.Errorf("unexpected benchmark command: %s %v", name, args)
			}
		},
	}
	b.ReportAllocs()
	for b.Loop() {
		networks, err := observer.Networks(b.Context())
		if err != nil || len(networks) != 3 {
			b.Fatalf("batched Docker observation failed: networks=%#v err=%v", networks, err)
		}
	}
}
