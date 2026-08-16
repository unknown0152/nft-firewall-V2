package containers

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func writeDockerFixture(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "docker")
	script := `#!/bin/sh
if [ "$1" = network ] && [ "$2" = ls ]; then
  printf '%s\n' '` + name + `'
  exit 0
fi
printf '%s\n' '[{"IPAM":{"Config":[{"Subnet":"172.19.0.0/16"},{"Subnet":"fd00:19::/64"}]}}]'
`
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestObserverRequiresDockerFirewallOwnershipDisabled(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "daemon.json")
	if err := os.WriteFile(path, []byte(`{"iptables":false,"ip6tables":false}`), 0o600); err != nil {
		t.Fatal(err)
	}
	o := Observer{DaemonConfig: path}
	ok, _, err := o.FirewallPolicy()
	if err != nil || !ok {
		t.Fatalf("safe Docker configuration rejected: ok=%t err=%v", ok, err)
	}
	if err := os.WriteFile(path, []byte(`{"iptables":true,"ip6tables":false}`), 0o600); err != nil {
		t.Fatal(err)
	}
	ok, _, err = o.FirewallPolicy()
	if err != nil || ok {
		t.Fatalf("unsafe Docker firewall ownership accepted: ok=%t err=%v", ok, err)
	}
}

func TestObserverReturnsValidatedDualStackNetworks(t *testing.T) {
	o := Observer{DockerBinary: writeDockerFixture(t, "br-test")}
	networks, err := o.Networks(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(networks) != 2 || networks[0].CIDR != "172.19.0.0/16" || networks[1].CIDR != "fd00:19::/64" {
		t.Fatalf("unexpected networks: %#v", networks)
	}
}

func TestObserverRejectsUnsafeNetworkName(t *testing.T) {
	o := Observer{DockerBinary: writeDockerFixture(t, "--config=/tmp/evil")}
	if _, err := o.Networks(context.Background()); err == nil {
		t.Fatal("unsafe Docker network name accepted")
	}
}
