package api

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

type testHandler struct{}

func (testHandler) Status(context.Context) (any, error) {
	return map[string]string{"status": "HEALTHY"}, nil
}

type fakeRawController struct {
	controlErr error
}

func (f fakeRawController) Control(callback func(uintptr)) error {
	if f.controlErr == nil {
		callback(42)
	}
	return f.controlErr
}

func TestPeerUcredFailsClosedOnInnerSyscallError(t *testing.T) {
	getterErr := errors.New("synthetic getsockopt failure")
	uid, ok := peerUcredFromRaw(fakeRawController{}, func(int, int, int) (*syscall.Ucred, error) {
		return nil, getterErr
	})
	if ok || uid != 0 {
		t.Fatalf("failed peer-credential syscall authenticated uid=%d ok=%t", uid, ok)
	}
	uid, ok = peerUcredFromRaw(fakeRawController{}, func(int, int, int) (*syscall.Ucred, error) {
		return &syscall.Ucred{Uid: 0}, nil
	})
	if !ok || uid != 0 {
		t.Fatalf("valid root peer credential rejected: uid=%d ok=%t", uid, ok)
	}
	uid, ok = peerUcredFromRaw(fakeRawController{controlErr: errors.New("synthetic control failure")}, func(int, int, int) (*syscall.Ucred, error) {
		return &syscall.Ucred{Uid: 0}, nil
	})
	if ok || uid != 0 {
		t.Fatalf("failed raw control authenticated uid=%d ok=%t", uid, ok)
	}
}

func TestControlConnectionQuotaIsIndependent(t *testing.T) {
	s := &Server{
		statusConnections:  make(chan struct{}, MaxConcurrentStatusConnections),
		controlConnections: make(chan struct{}, MaxConcurrentControlConnections),
	}
	for range MaxConcurrentStatusConnections {
		if _, ok := s.acquireConnection(false); !ok {
			t.Fatal("status quota filled early")
		}
	}
	if _, ok := s.acquireConnection(false); ok {
		t.Fatal("status quota exceeded its bound")
	}
	controlQuota, ok := s.acquireConnection(true)
	if !ok {
		t.Fatal("status saturation starved the independent control quota")
	}
	<-controlQuota
}

func TestPrepareSocketPathRejectsUnsafeObjectsAndParents(t *testing.T) {
	dir := secureTestDir(t)
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
	dir := filepath.Join(secureTestDir(t), "foreign")
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

type auditingHandler struct {
	testHandler
	events chan string
}

func (h auditingHandler) SecurityEvent(_ context.Context, event, detail string) {
	h.events <- event + ":" + detail
}

func TestStatusQuotaExhaustionDoesNotAmplifyDurableAudit(t *testing.T) {
	handler := auditingHandler{events: make(chan string, 2)}
	server := &Server{Handler: handler}

	statusServer, statusClient := net.Pipe()
	statusDone := make(chan struct{})
	go func() {
		server.rejectConnectionLimit(context.Background(), statusServer, false)
		close(statusDone)
	}()
	var response Response
	if err := json.NewDecoder(statusClient).Decode(&response); err != nil {
		t.Fatal(err)
	}
	<-statusDone
	_ = statusClient.Close()
	select {
	case event := <-handler.events:
		t.Fatalf("status quota exhaustion wrote durable security event %q", event)
	default:
	}

	controlServer, controlClient := net.Pipe()
	controlDone := make(chan struct{})
	go func() {
		server.rejectConnectionLimit(context.Background(), controlServer, true)
		close(controlDone)
	}()
	if err := json.NewDecoder(controlClient).Decode(&response); err != nil {
		t.Fatal(err)
	}
	<-controlDone
	_ = controlClient.Close()
	select {
	case event := <-handler.events:
		if event != "privileged_request_rejected:connection limit reached" {
			t.Fatalf("unexpected control quota event %q", event)
		}
	default:
		t.Fatal("control quota exhaustion was not audited")
	}
}

func TestMalformedPrivilegedRequestIsAuditedWithoutContent(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root peer is required to reach privileged request decoding")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir := secureTestDir(t)
	handler := auditingHandler{events: make(chan string, 1)}
	server := &Server{Handler: handler, StatusPath: filepath.Join(dir, "status.sock"), ControlPath: filepath.Join(dir, "control.sock")}
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(ctx) }()
	waitForUnixSocket(t, server.ControlPath, serveErr)
	conn, err := net.Dial("unix", server.ControlPath)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	secretLikeInput := "{not-valid-json-and-must-not-be-audited}\n"
	if _, err := io.WriteString(conn, secretLikeInput); err != nil {
		t.Fatal(err)
	}
	if _, err := bufio.NewReader(conn).ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	select {
	case event := <-handler.events:
		if event != "privileged_request_rejected:request JSON rejected" || strings.Contains(event, "not-valid") {
			t.Fatalf("unexpected or content-leaking audit event: %q", event)
		}
	case <-time.After(time.Second):
		t.Fatal("malformed privileged request was not audited")
	}
}

func TestUnixStatusAndControl(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir := secureTestDir(t)
	s := &Server{Handler: testHandler{}, StatusPath: filepath.Join(dir, "status.sock"), ControlPath: filepath.Join(dir, "control.sock")}
	serveErr := make(chan error, 1)
	go func() { serveErr <- s.Serve(ctx) }()
	waitForUnixSocket(t, s.StatusPath, serveErr)
	waitForUnixSocket(t, s.ControlPath, serveErr)
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
	if os.Geteuid() == 0 {
		if _, err := Call(ctx, s.ControlPath, Request{Op: "reconcile"}); err != nil {
			t.Fatal(err)
		}
	}
	cancel()
}

func waitForUnixSocket(t *testing.T, path string, serveErr <-chan error) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		info, err := os.Lstat(path)
		if err == nil && info.Mode()&os.ModeSocket != 0 {
			return
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("inspect Unix socket %s: %v", filepath.Base(path), err)
		}
		select {
		case err := <-serveErr:
			t.Fatalf("start Unix server: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("Unix socket %s did not become ready", filepath.Base(path))
		}
		time.Sleep(time.Millisecond)
	}
}
