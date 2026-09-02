// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

//go:build darwin

// Package esenforcer is KubeArmor's macOS host enforcer, backed by Apple's
// Endpoint Security framework. See getting-started/macos_endpoint_security_enforcer.md.
//
// The Go daemon compiles host Block process rules and pushes them, over an AF_UNIX
// socket, to the native `kubearmor-es-helper` (see enforcer/esenforcer/helper/).
// The helper answers ES AUTH_EXEC and, on a denial, sends back a complete BLOCKED
// event which is turned into a MatchedHostPolicy alert. If the helper cannot run
// (missing entitlement, not root, no binary) the enforcer stays observe-only and
// the eslogger audit path continues to record — but not prevent — Block violations.
package esenforcer

import (
	"bufio"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kubearmor/KubeArmor/KubeArmor/buildinfo"
	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// EnforcerType is the RuntimeEnforcer discriminator for this backend.
const EnforcerType = "AppleEndpointSecurity"

// ESEnforcer is the macOS Apple Endpoint Security host enforcer.
type ESEnforcer struct {
	Logger *fd.Feeder
	node   tp.Node

	helperPath string
	sockPath   string

	listener *net.UnixListener

	mu        sync.Mutex
	conn      net.Conn
	helperCmd *exec.Cmd
	rules     []esRule
	version   int

	enforced    atomic.Bool // helper connected & healthy
	unavailable atomic.Bool // helper reported it cannot run - stop respawning

	stop chan struct{}
	wg   sync.WaitGroup
}

// Available reports whether an Apple Endpoint Security enforcer can be created.
// It is always true on macOS; whether prevention is actually active is a runtime
// property (Enforcing()), not an enforcer-selection decision.
func Available() bool {
	return true
}

// NewESEnforcer creates the macOS host enforcer and, if the helper binary is
// present, starts the socket listener + helper supervisor. It never fails: on any
// problem it returns an observe-only enforcer so the eslogger/audit path stays live.
func NewESEnforcer(node tp.Node, logger *fd.Feeder) (*ESEnforcer, error) {
	e := &ESEnforcer{
		Logger:     logger,
		node:       node,
		helperPath: resolveHelperPath(),
		sockPath:   cfg.GlobalCfg.ESSocketPath,
		stop:       make(chan struct{}),
	}

	if _, err := os.Stat(e.helperPath); err != nil {
		logger.Printf("Apple Endpoint Security Enforcer: helper not found at %s - observe-only (Block rules recorded, not prevented). Set -esHelperPath to enable prevention.", e.helperPath)
		return e, nil
	}

	if err := e.listen(); err != nil {
		logger.Warnf("Apple Endpoint Security Enforcer: cannot open %s (%v) - observe-only", e.sockPath, err)
		return e, nil
	}

	e.wg.Add(2)
	go e.acceptLoop()
	go e.superviseHelper()

	logger.Printf("Apple Endpoint Security Enforcer: supervising %s, socket %s", e.helperPath, e.sockPath)
	return e, nil
}

func resolveHelperPath() string {
	if p := cfg.GlobalCfg.ESHelperPath; p != "" {
		return p
	}
	if exe, err := os.Executable(); err == nil {
		p := filepath.Join(filepath.Dir(exe), "kubearmor-es-helper")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "/usr/local/bin/kubearmor-es-helper"
}

func (e *ESEnforcer) listen() error {
	if err := os.MkdirAll(filepath.Dir(e.sockPath), 0o700); err != nil {
		return err
	}
	_ = os.Remove(e.sockPath)

	addr, err := net.ResolveUnixAddr("unix", e.sockPath)
	if err != nil {
		return err
	}
	l, err := net.ListenUnix("unix", addr)
	if err != nil {
		return err
	}
	_ = os.Chmod(e.sockPath, 0o600)
	e.listener = l
	return nil
}

// acceptLoop serves one helper connection at a time.
func (e *ESEnforcer) acceptLoop() {
	defer e.wg.Done()
	for {
		conn, err := e.listener.Accept()
		if err != nil {
			select {
			case <-e.stop:
				return
			default:
				return // listener closed
			}
		}
		e.handleConn(conn)
	}
}

func (e *ESEnforcer) handleConn(conn net.Conn) {
	e.setConn(conn)
	defer func() {
		e.setConn(nil)
		e.enforced.Store(false)
		_ = conn.Close()
	}()

	r := bufio.NewReaderSize(conn, 64*1024)
	for {
		payload, err := readFrame(r)
		if err != nil {
			return
		}
		f, err := parseFrame(payload)
		if err != nil {
			continue
		}
		switch f.Kind {
		case "HELLO":
			e.Logger.Printf("Apple Endpoint Security Enforcer: helper connected (v%d) - enforcing", f.Version)
			e.enforced.Store(true)
			e.pushRuleset()
		case "BLOCKED":
			e.pushBlockedLog(f)
		case "UNAVAILABLE":
			e.Logger.Warnf("Apple Endpoint Security Enforcer: helper unavailable (%s) - staying observe-only", f.Reason)
			e.unavailable.Store(true)
			e.enforced.Store(false)
		case "PONG":
		}
	}
}

func (e *ESEnforcer) setConn(c net.Conn) {
	e.mu.Lock()
	e.conn = c
	e.mu.Unlock()
}

// superviseHelper (re)spawns the helper until stop, or until it reports UNAVAILABLE.
func (e *ESEnforcer) superviseHelper() {
	defer e.wg.Done()
	backoff := time.Second
	for {
		select {
		case <-e.stop:
			return
		default:
		}
		if e.unavailable.Load() {
			return
		}

		cmd := exec.Command(e.helperPath, "-socket", e.sockPath) // #nosec G204 -- operator-configured path, fixed arg
		cmd.Stderr = &logWriter{logger: e.Logger, prefix: "es-helper"}
		if err := cmd.Start(); err != nil {
			e.Logger.Warnf("Apple Endpoint Security Enforcer: helper start failed: %v", err)
		} else {
			e.setHelperCmd(cmd)
			_ = cmd.Wait()
			e.setHelperCmd(nil)
		}

		select {
		case <-e.stop:
			return
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func (e *ESEnforcer) setHelperCmd(c *exec.Cmd) {
	e.mu.Lock()
	e.helperCmd = c
	e.mu.Unlock()
}

// UpdateHostSecurityPolicies recompiles the Block ruleset and pushes it to the helper.
func (e *ESEnforcer) UpdateHostSecurityPolicies(secPolicies []tp.HostSecurityPolicy) {
	if e == nil {
		return
	}
	rules := compileHostRules(secPolicies)

	e.mu.Lock()
	e.rules = rules
	e.version++
	e.mu.Unlock()

	nProc, nFile := 0, 0
	for _, r := range rules {
		if r.Operation == "file" {
			nFile++
		} else {
			nProc++
		}
	}
	e.Logger.Printf("Apple Endpoint Security Enforcer: %d Block rule(s) compiled from %d host policies (%d process, %d file)", len(rules), len(secPolicies), nProc, nFile)
	e.pushRuleset()
}

func (e *ESEnforcer) pushRuleset() {
	e.mu.Lock()
	conn := e.conn
	data := serializeRuleset(e.version, e.rules)
	e.mu.Unlock()

	if conn == nil {
		return
	}
	if err := writeFrame(conn, data); err != nil {
		e.Logger.Warnf("Apple Endpoint Security Enforcer: pushing ruleset failed: %v", err)
	}
}

func (e *ESEnforcer) pushBlockedLog(f esFrame) {
	ts, tstr := kl.GetDateTimeNow()

	operation := f.Op
	if operation == "" {
		operation = "Process"
	}
	data := f.Data
	if data == "" {
		data = "syscall=execve"
	}

	resource := f.Target
	if operation == "Process" && len(f.Args) > 1 {
		resource = f.Target + " " + strings.Join(f.Args[1:], " ")
	}
	cwd := f.Cwd
	if cwd == "" {
		cwd = "/"
	} else {
		cwd = strings.TrimRight(cwd, "/") + "/"
	}

	log := tp.Log{
		Timestamp:         ts,
		UpdatedTime:       tstr,
		Type:              "MatchedHostPolicy",
		Operation:         operation,
		Action:            "Block",
		Result:            "Permission denied",
		Enforcer:          EnforcerType,
		PolicyName:        f.Rule,
		Severity:          strconv.Itoa(f.Severity),
		Message:           f.Message,
		Source:            f.ParentExe,
		Resource:          resource,
		ProcessName:       f.Exe,
		ParentProcessName: f.ParentExe,
		HostPID:           f.PID,
		HostPPID:          f.PPID,
		PID:               f.PID,
		PPID:              f.PPID,
		UID:               f.EUID,
		Cwd:               cwd,
		TTY:               f.TTY,
		Data:              data,
		KubeArmorVersion:  buildinfo.GitSummary,
	}
	e.Logger.PushLog(log)
}

// Enforcing reports whether the helper is connected and actively denying.
func (e *ESEnforcer) Enforcing() bool {
	return e != nil && e.enforced.Load()
}

// DestroyESEnforcer stops the supervisor, kills the helper, and closes the socket.
func (e *ESEnforcer) DestroyESEnforcer() error {
	if e == nil {
		return nil
	}
	select {
	case <-e.stop:
	default:
		close(e.stop)
	}

	e.mu.Lock()
	if e.helperCmd != nil && e.helperCmd.Process != nil {
		_ = e.helperCmd.Process.Kill()
	}
	conn := e.conn
	e.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
	if e.listener != nil {
		_ = e.listener.Close()
	}
	_ = os.Remove(e.sockPath)

	done := make(chan struct{})
	go func() { e.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
	}
	return nil
}

// AddContainerIDToMap is a no-op on macOS (no containers / namespaces).
func (e *ESEnforcer) AddContainerIDToMap(containerID string, pidns, mntns uint32) {}

// DeleteContainerIDFromMap is a no-op on macOS.
func (e *ESEnforcer) DeleteContainerIDFromMap(containerID string) {}

// UpdateSecurityPolicies is a no-op on macOS (host scope only).
func (e *ESEnforcer) UpdateSecurityPolicies(endPoint tp.EndPoint) {}

// logWriter adapts helper stderr into feeder log lines, one per '\n'. It uses
// Printf (INFO) so helper diagnostics appear at the same level as the rest of the
// enforcer's startup logging rather than being filtered as warnings.
type logWriter struct {
	logger *fd.Feeder
	prefix string
	buf    []byte
}

func (w *logWriter) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	for {
		i := strings.IndexByte(string(w.buf), '\n')
		if i < 0 {
			break
		}
		line := strings.TrimSpace(string(w.buf[:i]))
		w.buf = w.buf[i+1:]
		if line != "" {
			w.logger.Printf("%s: %s", w.prefix, line)
		}
	}
	return len(p), nil
}
