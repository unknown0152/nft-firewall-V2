package api

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type testHandler struct{}

func (testHandler) Status(context.Context) (any, error) {
	return map[string]string{"status": "HEALTHY"}, nil
}

func TestPrepareSocketPathRejectsUnsafeObjectsAndParents(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "control.sock")
	if err := os.WriteFile(regular, []byte("do not remove"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := prepareSocketPath(regular); err == nil {
		t.Fatal("regular file at socket path was removed")
	}
	if data, err := os.ReadFile(regular); err != nil || string(data) != "do not remove" {
		t.Fatal("regular file at socket path was modified")
	}
	unsafe := filepath.Join(dir, "unsafe")
	if err := os.Mkdir(unsafe, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafe, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := prepareSocketPath(filepath.Join(unsafe, "status.sock")); err == nil {
		t.Fatal("group/other-writable socket parent accepted")
	}
}

func TestPrepareSocketPathRejectsForeignOwnedParent(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing ownership requires root")
	}
	dir := filepath.Join(t.TempDir(), "foreign")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(dir, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if err := prepareSocketPath(filepath.Join(dir, "status.sock")); err == nil {
		t.Fatal("foreign-owned socket parent accepted")
	}
}

func FuzzDecodeRequest(f *testing.F) {
	f.Add([]byte(`{"op":"status"}`))
	f.Add([]byte(`{"op":"apply","safe":true}`))
	f.Add([]byte(`{"op":"apply","unsafe":true}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = decodeRequest(bytes.NewReader(data))
	})
}

func TestStrictRequestSchema(t *testing.T) {
	if _, err := decodeRequest(strings.NewReader(`{"op":"status","claimed_user":"root"}`)); err == nil {
		t.Fatal("unknown security field accepted")
	}
	if _, err := decodeRequest(strings.NewReader(`{"op":"status"} {"op":"status"}`)); err == nil {
		t.Fatal("multiple JSON values accepted")
	}
}

func TestResponseDecoderIsBoundedAndSingleValue(t *testing.T) {
	if _, err := readResponse(strings.NewReader(`{"ok":true}{"ok":true}`)); err == nil {
		t.Fatal("multiple API response values accepted")
	}
	oversize := bytes.Repeat([]byte(" "), MaxResponseBytes+1)
	if _, err := readResponse(bytes.NewReader(oversize)); err == nil {
		t.Fatal("oversized API response accepted")
	}
}

func TestRemoteErrorIsTyped(t *testing.T) {
	err := RemoteError{Message: "candidate rejected"}
	var remote RemoteError
	if !errors.As(err, &remote) || remote.Error() != "candidate rejected" {
		t.Fatalf("remote response error lost its type: %v", err)
	}
}

func TestOperationSpecificRequestSchema(t *testing.T) {
	for _, req := range []Request{
		{Op: "status", Address: "203.0.113.1"},
		{Op: "commit"},
		{Op: "allow-add", Address: "203.0.113.1", Source: "manual"},
		{Op: "allow-add", Address: "203.0.113.1"},
		{Op: "allow-add", Address: "203.0.113.1", ExpiresSec: 365*24*60*60 + 1},
		{Op: "block-add", Address: "203.0.113.1", Source: "threatfeed/forged"},
		{Op: "block-remove", ClaimID: -1},
		{Op: "allow-remove", ClaimID: -1},
		{Op: "apply"},
		{Op: "apply", Safe: true, Unsafe: true},
		{Op: "claims", Limit: 1001},
		{Op: "claims", Offset: -1},
		{Op: "block-add", Address: "203.0.113.1", Source: "manual", Reason: strings.Repeat("x", 1025)},
	} {
		if err := validateRequest(req, true); err == nil {
			t.Fatalf("invalid request accepted: %#v", req)
		}
	}
	if err := validateRequest(Request{Op: "block-add", Address: "203.0.113.1", Source: "manual"}, true); err != nil {
		t.Fatal(err)
	}
	if err := validateRequest(Request{Op: "allow-add", Address: "203.0.113.1", ExpiresSec: 900}, true); err != nil {
		t.Fatal(err)
	}
	if err := validateRequest(Request{Op: "claims", Limit: 1000, Offset: 100}, true); err != nil {
		t.Fatal(err)
	}
	if err := validateRequest(Request{Op: "apply", Safe: true}, true); err != nil {
		t.Fatal(err)
	}
	if err := validateRequest(Request{Op: "apply", Unsafe: true}, true); err != nil {
		t.Fatal(err)
	}
}
func (testHandler) Control(_ context.Context, r Request) (any, error) { return r.Op, nil }
func TestUnixStatusAndControl(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir := t.TempDir()
	s := &Server{Handler: testHandler{}, StatusPath: filepath.Join(dir, "status.sock"), ControlPath: filepath.Join(dir, "control.sock")}
	go func() { _ = s.Serve(ctx) }()
	time.Sleep(20 * time.Millisecond)
	resp, err := Call(ctx, s.StatusPath, Request{Op: "status"})
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "operation not permitted") {
			t.Skip("sandbox denies AF_UNIX connects")
		}
		t.Fatal(err)
	}
	if !resp.OK {
		t.Fatal(resp.Error)
	}
	if _, err := Call(ctx, s.ControlPath, Request{Op: "reconcile"}); err != nil {
		t.Fatal(err)
	}
	cancel()
}
