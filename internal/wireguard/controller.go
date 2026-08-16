package wireguard

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const maxWGOutput = 64 << 10

var interfaceName = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)

type CommandRunner interface {
	Run(context.Context, ...string) (string, error)
}

type ExecRunner struct{ Binary string }

func (r ExecRunner) Run(ctx context.Context, args ...string) (string, error) {
	binary := r.Binary
	if binary == "" {
		binary = "wg"
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	var output bytes.Buffer
	cmd.Stdout = &boundedWriter{Buffer: &output, Remaining: maxWGOutput}
	if err := cmd.Run(); err != nil {
		return "", errors.New("WireGuard command failed")
	}
	if output.Len() >= maxWGOutput {
		return "", errors.New("WireGuard command output exceeded limit")
	}
	return output.String(), nil
}

type boundedWriter struct {
	Buffer    *bytes.Buffer
	Remaining int
}

func (w *boundedWriter) Write(p []byte) (int, error) {
	original := len(p)
	if len(p) > w.Remaining {
		p = p[:w.Remaining]
	}
	if len(p) > 0 {
		_, _ = w.Buffer.Write(p)
		w.Remaining -= len(p)
	}
	return original, nil
}

type Controller struct{ Runner CommandRunner }

type Observation struct {
	Interface       string     `json:"interface"`
	Available       bool       `json:"available"`
	Healthy         bool       `json:"healthy"`
	PeerCount       int        `json:"peer_count"`
	EndpointCount   int        `json:"endpoint_count"`
	LatestHandshake *time.Time `json:"latest_handshake,omitempty"`
	AgeSeconds      int64      `json:"age_seconds,omitempty"`
	Reason          string     `json:"reason,omitempty"`
}

func (c Controller) runner() CommandRunner {
	if c.Runner != nil {
		return c.Runner
	}
	return ExecRunner{}
}

// SetEndpoint updates exactly one validated peer. It returns false when the
// current endpoint already matches the desired endpoint.
func (c Controller) SetEndpoint(ctx context.Context, iface, address string, port int) (bool, error) {
	if !interfaceName.MatchString(iface) {
		return false, errors.New("invalid WireGuard interface")
	}
	ip, err := netip.ParseAddr(address)
	if err != nil || ip.IsUnspecified() || ip.IsMulticast() || port < 1 || port > 65535 {
		return false, errors.New("invalid WireGuard endpoint")
	}
	peersOutput, err := c.runner().Run(ctx, "show", iface, "peers")
	if err != nil {
		return false, err
	}
	peers := strings.Fields(peersOutput)
	if len(peers) != 1 || !validPublicKey(peers[0]) {
		return false, fmt.Errorf("endpoint refresh requires exactly one valid WireGuard peer, got %d", len(peers))
	}
	desired := net.JoinHostPort(ip.String(), strconv.Itoa(port))
	endpointsOutput, err := c.runner().Run(ctx, "show", iface, "endpoints")
	if err != nil {
		return false, err
	}
	fields := strings.Fields(endpointsOutput)
	if len(fields) == 2 && fields[0] == peers[0] && fields[1] == desired {
		return false, nil
	}
	if _, err := c.runner().Run(ctx, "set", iface, "peer", peers[0], "endpoint", desired); err != nil {
		return false, err
	}
	return true, nil
}

func (c Controller) Observe(ctx context.Context, iface string, healthyWithin time.Duration) Observation {
	observation := Observation{Interface: iface}
	if !interfaceName.MatchString(iface) {
		observation.Reason = "invalid configured interface"
		return observation
	}
	peersOutput, err := c.runner().Run(ctx, "show", iface, "latest-handshakes")
	if err != nil {
		observation.Reason = "interface unavailable"
		return observation
	}
	observation.Available = true
	latest := int64(0)
	for _, line := range strings.Split(peersOutput, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || !validPublicKey(fields[0]) {
			continue
		}
		observation.PeerCount++
		value, parseErr := strconv.ParseInt(fields[1], 10, 64)
		if parseErr == nil && value > latest {
			latest = value
		}
	}
	endpointsOutput, endpointErr := c.runner().Run(ctx, "show", iface, "endpoints")
	if endpointErr == nil {
		for _, line := range strings.Split(endpointsOutput, "\n") {
			fields := strings.Fields(line)
			if len(fields) == 2 && validPublicKey(fields[0]) && fields[1] != "(none)" {
				observation.EndpointCount++
			}
		}
	}
	if latest == 0 {
		observation.Reason = "no completed handshake"
		return observation
	}
	timestamp := time.Unix(latest, 0).UTC()
	observation.LatestHandshake = &timestamp
	age := time.Since(timestamp)
	if age < 0 {
		age = 0
	}
	observation.AgeSeconds = int64(age.Seconds())
	if healthyWithin <= 0 {
		healthyWithin = 3 * time.Minute
	}
	observation.Healthy = observation.PeerCount > 0 && age <= healthyWithin
	if !observation.Healthy {
		observation.Reason = "latest handshake is stale"
	}
	return observation
}

func validPublicKey(raw string) bool {
	decoded, err := base64.StdEncoding.DecodeString(raw)
	return err == nil && len(decoded) == 32
}
