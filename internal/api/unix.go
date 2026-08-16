// Package api exposes the narrow local status/control boundary.
package api

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const MaxRequestBytes = 64 << 10
const MaxConcurrentConnections = 64

type Request struct {
	Op         string `json:"op"`
	Generation uint64 `json:"generation,omitempty"`
	Safe       bool   `json:"safe,omitempty"`
	Address    string `json:"address,omitempty"`
	ClaimID    int64  `json:"claim_id,omitempty"`
	Source     string `json:"source,omitempty"`
	Reason     string `json:"reason,omitempty"`
	ExpiresSec int64  `json:"expires_seconds,omitempty"`
}

type Response struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	Data  any    `json:"data,omitempty"`
}

type Handler interface {
	Status(context.Context) (any, error)
	Control(context.Context, Request) (any, error)
}

type securityEventHandler interface {
	SecurityEvent(context.Context, string, string)
}

type Server struct {
	Handler                 Handler
	StatusPath, ControlPath string
	listeners               []net.Listener
	connections             chan struct{}
}

func (s *Server) Serve(ctx context.Context) error {
	if s.Handler == nil {
		return errors.New("API handler is nil")
	}
	if s.StatusPath == "" || s.ControlPath == "" {
		return errors.New("socket paths are required")
	}
	for _, p := range []string{s.StatusPath, s.ControlPath} {
		if err := prepareSocketPath(p); err != nil {
			return err
		}
	}
	status, err := net.Listen("unix", s.StatusPath)
	if err != nil {
		return fmt.Errorf("listen status socket: %w", err)
	}
	control, err := net.Listen("unix", s.ControlPath)
	if err != nil {
		status.Close()
		return fmt.Errorf("listen control socket: %w", err)
	}
	s.listeners = []net.Listener{status, control}
	if err := os.Chmod(s.StatusPath, 0o660); err != nil {
		status.Close()
		control.Close()
		return fmt.Errorf("secure status socket: %w", err)
	}
	if err := os.Chmod(s.ControlPath, 0o600); err != nil {
		status.Close()
		control.Close()
		return fmt.Errorf("secure control socket: %w", err)
	}
	defer os.Remove(s.StatusPath)
	defer os.Remove(s.ControlPath)
	s.connections = make(chan struct{}, MaxConcurrentConnections)
	errCh := make(chan error, 2)
	go s.acceptLoop(ctx, status, false, errCh)
	go s.acceptLoop(ctx, control, true, errCh)
	select {
	case <-ctx.Done():
		for _, l := range s.listeners {
			_ = l.Close()
		}
		return ctx.Err()
	case e := <-errCh:
		return e
	}
}

func (s *Server) acceptLoop(ctx context.Context, l net.Listener, control bool, errCh chan<- error) {
	for {
		conn, err := l.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				errCh <- err
				return
			}
		}
		select {
		case s.connections <- struct{}{}:
			go func() {
				defer func() { <-s.connections }()
				s.handle(ctx, conn, control)
			}()
		default:
			writeResponse(conn, Response{Error: "server connection limit reached"})
			_ = conn.Close()
			s.securityEvent(ctx, "privileged_request_rejected", "connection limit reached")
		}
	}
}

func (s *Server) handle(ctx context.Context, conn net.Conn, control bool) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	uid, havePeer := peerUcred(conn)
	if control && (!havePeer || uid != 0) {
		s.securityEvent(ctx, "control_access_denied", fmt.Sprintf("peer_uid=%d credential_available=%t", uid, havePeer))
		writeResponse(conn, Response{Error: "control socket requires root peer credentials"})
		return
	}
	reader := bufio.NewReader(io.LimitReader(conn, MaxRequestBytes+1))
	frame, err := reader.ReadBytes('\n')
	if err != nil && err != io.EOF {
		writeResponse(conn, Response{Error: "invalid request frame: " + err.Error()})
		return
	}
	if len(frame) == 0 || len(frame) > MaxRequestBytes {
		writeResponse(conn, Response{Error: "invalid request frame size"})
		return
	}
	req, err := decodeRequest(bytes.NewReader(frame))
	if err != nil {
		writeResponse(conn, Response{Error: "invalid request: " + err.Error()})
		return
	}
	if req.Op == "" {
		writeResponse(conn, Response{Error: "missing op"})
		return
	}
	if err := validateRequest(req, control); err != nil {
		if control {
			s.securityEvent(ctx, "privileged_request_rejected", "operation="+req.Op)
		}
		writeResponse(conn, Response{Error: "invalid request: " + err.Error()})
		return
	}
	var data any
	var handlerErr error
	if control {
		data, handlerErr = s.Handler.Control(ctx, req)
	} else {
		if req.Op != "status" {
			writeResponse(conn, Response{Error: "status socket is read-only"})
			return
		}
		data, handlerErr = s.Handler.Status(ctx)
	}
	if handlerErr != nil {
		if control {
			s.securityEvent(ctx, "privileged_request_failed", "operation="+req.Op)
		}
		writeResponse(conn, Response{Error: handlerErr.Error()})
		return
	}
	writeResponse(conn, Response{OK: true, Data: data})
}

func (s *Server) securityEvent(ctx context.Context, event, detail string) {
	if handler, ok := s.Handler.(securityEventHandler); ok {
		handler.SecurityEvent(ctx, event, detail)
	}
}

func validateRequest(r Request, control bool) error {
	if !control && r.Op != "status" {
		return errors.New("status socket is read-only")
	}
	plain := r.Generation == 0 && !r.Safe && r.Address == "" && r.ClaimID == 0 && r.Source == "" && r.Reason == "" && r.ExpiresSec == 0
	switch r.Op {
	case "status", "claims", "audit", "plan", "reconcile", "wg-refresh":
		if !plain {
			return errors.New("operation does not accept fields")
		}
	case "apply":
		if r.Generation != 0 || r.Address != "" || r.ClaimID != 0 || r.Source != "" || r.Reason != "" || r.ExpiresSec != 0 {
			return errors.New("apply accepts only safe")
		}
	case "commit", "rollback":
		if r.Generation == 0 || r.Safe || r.Address != "" || r.ClaimID != 0 || r.Source != "" || r.Reason != "" || r.ExpiresSec != 0 {
			return errors.New("generation operation requires only a positive generation")
		}
	case "block-add":
		if r.Address == "" || r.Generation != 0 || r.Safe || r.ClaimID != 0 || r.Source != "manual" || r.ExpiresSec < 0 || r.ExpiresSec > 365*24*60*60 {
			return errors.New("block-add requires an address, source=manual, optional reason, and a bounded expiry")
		}
	case "allow-add":
		if r.Address == "" || r.Generation != 0 || r.Safe || r.ClaimID != 0 || r.Source != "" || r.ExpiresSec < 0 || r.ExpiresSec > 365*24*60*60 {
			return errors.New("allow-add requires an address, optional reason, and a bounded expiry")
		}
	case "block-remove":
		if r.ClaimID <= 0 || r.Generation != 0 || r.Safe || r.Address != "" || r.Source != "" || r.Reason != "" || r.ExpiresSec != 0 {
			return errors.New("block-remove requires only a positive claim_id")
		}
	default:
		return fmt.Errorf("unsupported operation %q", r.Op)
	}
	return nil
}

func decodeRequest(r io.Reader) (Request, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	var req Request
	if err := dec.Decode(&req); err != nil {
		return Request{}, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return Request{}, errors.New("multiple JSON values are not allowed")
	}
	return req, nil
}

func writeResponse(w io.Writer, r Response) { _ = json.NewEncoder(w).Encode(r) }

func peerUcred(conn net.Conn) (uint32, bool) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, false
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, false
	}
	var uid uint32
	err = raw.Control(func(fd uintptr) {
		cred, e := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if e == nil {
			uid = cred.Uid
		}
	})
	return uid, err == nil
}

func prepareSocketPath(path string) error {
	if path == "" {
		return errors.New("empty socket path")
	}
	abs, err := filepath.Abs(path)
	if err != nil || abs != path {
		return errors.New("socket path must be absolute")
	}
	parent := filepath.Dir(abs)
	if err := os.MkdirAll(parent, 0o750); err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil || resolved != parent {
		return errors.New("socket parent path contains a symlink")
	}
	parentInfo, err := os.Stat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode().Perm()&0o022 != 0 {
		return errors.New("socket parent must not be group/other writable")
	}
	if fi, err := os.Lstat(abs); err == nil {
		stat, ok := fi.Sys().(*syscall.Stat_t)
		if fi.Mode()&os.ModeSymlink != 0 || fi.Mode()&os.ModeSocket == 0 || !ok || stat.Uid != uint32(os.Geteuid()) {
			return errors.New("existing socket path is not an owned socket")
		}
		if err := os.Remove(abs); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func Call(ctx context.Context, path string, req Request) (Response, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return Response{}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return Response{}, err
	}
	var resp Response
	if err := json.NewDecoder(io.LimitReader(conn, MaxRequestBytes)).Decode(&resp); err != nil {
		return Response{}, err
	}
	if !resp.OK {
		return resp, errors.New(resp.Error)
	}
	return resp, nil
}
