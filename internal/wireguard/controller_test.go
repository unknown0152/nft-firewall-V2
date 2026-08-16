package wireguard

import (
	"context"
	"encoding/base64"
	"reflect"
	"strconv"
	"testing"
	"time"
)

type fakeWGRunner struct {
	endpoint  string
	handshake string
	calls     [][]string
}

func (r *fakeWGRunner) Run(_ context.Context, args ...string) (string, error) {
	r.calls = append(r.calls, append([]string(nil), args...))
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	if len(args) == 3 && args[2] == "peers" {
		return key + "\n", nil
	}
	if len(args) == 3 && args[2] == "latest-handshakes" {
		return key + "\t" + r.handshake + "\n", nil
	}
	if len(args) == 3 && args[2] == "endpoints" {
		return key + "\t" + r.endpoint + "\n", nil
	}
	return "", nil
}

func TestControllerObservationContainsNoPeerOrEndpointMaterial(t *testing.T) {
	runner := &fakeWGRunner{endpoint: "198.51.100.1:51820", handshake: strconv.FormatInt(time.Now().Unix(), 10)}
	observation := (Controller{Runner: runner}).Observe(context.Background(), "wg0", time.Minute)
	if !observation.Available || !observation.Healthy || observation.PeerCount != 1 || observation.EndpointCount != 1 || observation.LatestHandshake == nil {
		t.Fatalf("unexpected observation: %#v", observation)
	}
}

func TestControllerUpdatesOnlyChangedValidatedEndpoint(t *testing.T) {
	runner := &fakeWGRunner{endpoint: "198.51.100.1:51820"}
	changed, err := (Controller{Runner: runner}).SetEndpoint(context.Background(), "wg0", "198.51.100.2", 51820)
	if err != nil || !changed {
		t.Fatalf("endpoint was not updated: changed=%t err=%v", changed, err)
	}
	wantSet := []string{"set", "wg0", "peer", base64.StdEncoding.EncodeToString(make([]byte, 32)), "endpoint", "198.51.100.2:51820"}
	if !reflect.DeepEqual(runner.calls[len(runner.calls)-1], wantSet) {
		t.Fatalf("unexpected wg arguments: %#v", runner.calls)
	}
	runner = &fakeWGRunner{endpoint: "[2001:db8::2]:51820"}
	changed, err = (Controller{Runner: runner}).SetEndpoint(context.Background(), "wg0", "2001:db8::2", 51820)
	if err != nil || changed || len(runner.calls) != 2 {
		t.Fatalf("unchanged IPv6 endpoint was modified: changed=%t err=%v calls=%v", changed, err, runner.calls)
	}
}

func TestControllerRejectsMultiplePeers(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	runner := commandRunnerFunc(func(_ context.Context, args ...string) (string, error) { return key + "\n" + key + "\n", nil })
	if _, err := (Controller{Runner: runner}).SetEndpoint(context.Background(), "wg0", "198.51.100.2", 51820); err == nil {
		t.Fatal("ambiguous multi-peer endpoint update accepted")
	}
}

type commandRunnerFunc func(context.Context, ...string) (string, error)

func (f commandRunnerFunc) Run(ctx context.Context, args ...string) (string, error) {
	return f(ctx, args...)
}
