// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

//go:build darwin

package monitor

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// esloggerBinary is Apple's built-in Endpoint Security event streamer (macOS 13+).
const esloggerBinary = "/usr/bin/eslogger"

// esloggerBaseEvents is the NOTIFY event set KubeArmor always subscribes to for
// macOS host visibility and Audit-mode policy-violation detection. `open` is added
// on top of this only when file visibility is enabled (it is a firehose and
// eslogger has no path filter).
//
// The session/login/auth events (openssh_login/logout, login_login/logout,
// lw_session_login/logout/lock/unlock, screensharing_attach/detach, su, sudo,
// authentication) are unconditional, not visibility-gated: they fire at human
// rate (a handful a day), and — unlike file opens — an unmatched "Syscall"
// operation log is silently dropped by the host branch of
// feeder.UpdateMatchedPolicy (it has no bare-visibility fallback for that
// operation, same as on Linux today), so subscribing to them costs nothing when
// no policy references them.
var esloggerBaseEvents = []string{
	"exec", "exit", "fork",
	"create", "unlink", "rename", "truncate",
	"setmode", "setowner",
	"openssh_login", "openssh_logout",
	"login_login", "login_logout",
	"lw_session_login", "lw_session_logout", "lw_session_lock", "lw_session_unlock",
	"screensharing_attach", "screensharing_detach",
	"su", "sudo", "authentication",
}

// esProc is the per-pid state captured at exec, reused to enrich later file events
// with cwd / full command line / parent identity that are not carried on the
// file-event message itself.
type esProc struct {
	ExePath string
	Cwd     string
	Args    []string
	CDHash  string
}

// InitESLogger spawns and supervises `eslogger`, normalises each JSON NOTIFY record
// into a tp.Log, and pushes it through the feeder. It runs until StopChan is closed.
//
// Every macOS event is host scope (no containers / namespaces). The feeder's
// UpdateMatchedPolicy then classifies each record as a HostLog (visibility) or a
// MatchedHostPolicy alert (Audit rule / audit posture).
func (mon *SystemMonitor) InitESLogger() {
	if _, err := os.Stat(esloggerBinary); err != nil {
		mon.Logger.Warnf("%s not found; macOS visibility & audit alerts are disabled (needs macOS 13+)", esloggerBinary)
		return
	}

	events := mon.esloggerEvents()
	mon.Logger.Printf("Starting macOS eslogger telemetry: %s", strings.Join(events, ","))

	backoff := time.Second
	for {
		select {
		case <-StopChan:
			return
		default:
		}

		// recompute in case host visibility changed since the last (re)start
		events = mon.esloggerEvents()
		err, stderr := mon.runESLogger(events)

		select {
		case <-StopChan:
			return
		default:
		}

		mon.Logger.Warnf("eslogger stopped (%v)%s; retrying in %s", err, esloggerHint(stderr), backoff)
		select {
		case <-StopChan:
			return
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

// esloggerEvents is the base set plus `open` when file visibility is on.
func (mon *SystemMonitor) esloggerEvents() []string {
	events := append([]string(nil), esloggerBaseEvents...)
	if mon.fileVisibilityEnabled() {
		events = append(events, "open")
	}
	return events
}

func (mon *SystemMonitor) fileVisibilityEnabled() bool {
	if mon.Node == nil || mon.NodeLock == nil {
		return false
	}
	nodeLock := *mon.NodeLock
	nodeLock.RLock()
	defer nodeLock.RUnlock()
	return mon.Node.FileVisibilityEnabled
}

// runESLogger runs one `eslogger` process to completion, streaming its stdout.
// It returns the process error and whatever eslogger wrote to stderr (its error
// messages, e.g. an Endpoint Security connect failure).
func (mon *SystemMonitor) runESLogger(events []string) (error, string) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		select {
		case <-StopChan:
			cancel()
		case <-ctx.Done():
		}
	}()

	args := append([]string{"--format", "json"}, events...)
	cmd := exec.CommandContext(ctx, esloggerBinary, args...) // #nosec G204 -- fixed binary + static event list

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err, ""
	}
	if err := cmd.Start(); err != nil {
		return err, stderr.String()
	}

	pidMap := map[int32]*esProc{}

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 1024*1024), 8*1024*1024)
	for scanner.Scan() {
		mon.handleESRecord(scanner.Bytes(), pidMap)
	}

	werr := cmd.Wait()
	if serr := scanner.Err(); serr != nil {
		return serr, stderr.String()
	}
	return werr, stderr.String()
}

// esloggerHint turns eslogger's stderr into an actionable one-liner.
func esloggerHint(stderr string) string {
	stderr = strings.TrimSpace(stderr)
	if stderr == "" {
		return ". Run KubeArmor as root (sudo) and grant Full Disk Access to the process (or the terminal that launches it) in System Settings > Privacy & Security > Full Disk Access"
	}
	lines := strings.Split(stderr, "\n")
	last := ""
	for _, l := range lines {
		if s := strings.TrimSpace(l); s != "" {
			last = s
		}
	}
	msg := ": " + last
	switch {
	case strings.Contains(stderr, "ERR_NOT_PRIVILEGED"):
		return msg + " -- run KubeArmor as root (sudo)"
	case strings.Contains(stderr, "ERR_NOT_PERMITTED"), strings.Contains(stderr, "TCC"), strings.Contains(stderr, "Full Disk Access"):
		return msg + " -- grant Full Disk Access to the process (or the terminal that launches it) in System Settings > Privacy & Security > Full Disk Access, then fully quit and relaunch it"
	default:
		return msg
	}
}

// handleESRecord parses one eslogger JSON line and pushes a tp.Log.
func (mon *SystemMonitor) handleESRecord(line []byte, pidMap map[int32]*esProc) {
	var m map[string]any
	if err := json.Unmarshal(line, &m); err != nil {
		return
	}

	event, _ := m["event"].(map[string]any)
	if len(event) == 0 {
		return
	}
	var evType string
	var evBody map[string]any
	for k, v := range event {
		evType = k
		evBody, _ = v.(map[string]any)
		break
	}

	proc, _ := m["process"].(map[string]any)
	pid := digInt(proc, "audit_token", "pid")
	if pid == 0 {
		pid = digInt(proc, "pid")
	}
	ppid := digInt(proc, "ppid")
	uid := digInt(proc, "audit_token", "euid")
	pidVersion := digInt(proc, "audit_token", "pidversion")
	actingExe := digStr(proc, "executable", "path")
	actingTTY := digStr(proc, "tty", "path")
	actingHash := digCDHash(proc, "cdhash")

	switch evType {
	case "exit":
		delete(pidMap, pid)
		return
	case "fork":
		child := digInt(evBody, "child", "audit_token", "pid")
		if child == 0 {
			child = digInt(evBody, "child", "pid")
		}
		if child != 0 {
			cwd := ""
			if p := pidMap[pid]; p != nil {
				cwd = p.Cwd
			}
			pidMap[child] = &esProc{ExePath: actingExe, Cwd: cwd, CDHash: actingHash}
		}
		return
	case "exec":
		target := digStr(evBody, "target", "executable", "path")
		if target == "" {
			return
		}
		args := digStrSlice(evBody, "args")
		if len(args) == 0 {
			args = digStrSlice(evBody, "target", "args")
		}
		cwd := digStr(evBody, "cwd", "path")
		targetHash := digCDHash(evBody, "target", "cdhash")
		if targetHash == "" {
			targetHash = actingHash
		}
		pidMap[pid] = &esProc{ExePath: target, Cwd: cwd, Args: args, CDHash: targetHash}

		resource := target
		if len(args) > 1 {
			resource = target + " " + strings.Join(args[1:], " ")
		}
		log := mon.newESLog("Process", resource, "syscall=execve", pid, ppid, uid, pidVersion)
		log.ProcessName = target
		log.ParentProcessName = actingExe
		log.Source = actingExe // matches Linux: exec Source == ParentProcessName
		log.Cwd = withTrailingSlash(cwd)
		if t := digStr(evBody, "target", "tty", "path"); t != "" {
			log.TTY = t
		} else {
			log.TTY = actingTTY
		}
		log.OID = digInt(evBody, "target", "executable", "stat", "st_uid")
		log.ExecEvent.ExecutableName = filepath.Base(target)
		setHashes(&log, targetHash, pidHash(pidMap, ppid))
		mon.Logger.PushLog(log)
		return

	case "openssh_login", "openssh_logout", "login_login", "login_logout",
		"lw_session_login", "lw_session_logout", "lw_session_lock", "lw_session_unlock",
		"screensharing_attach", "screensharing_detach", "su", "sudo", "authentication":
		// Session/login/auth events. ES only ever NOTIFYs these (no AUTH_* variant
		// exists for any of them - verified against ESTypes.h - so there is nothing
		// to block, only to audit). Operation "Syscall" reuses KubeArmor's existing
		// syscall-audit policy category (spec.syscalls.matchSyscalls) unchanged:
		// its rule type has no Action field, so a rule against these can only ever
		// be Audit, matching what the OS actually offers.
		resource, source, data := esSessionFields(evType, evBody)
		if resource == "" && source == "" {
			return
		}
		log := mon.newESLog("Syscall", resource, data, pid, ppid, uid, pidVersion)
		log.ProcessName = actingExe
		log.ParentProcessName = pidExe(pidMap, ppid)
		log.TTY = actingTTY
		if source != "" {
			log.Source = source
		} else {
			log.Source = actingExe
		}
		log.Cwd = "/"
		setHashes(&log, actingHash, pidHash(pidMap, ppid))
		mon.Logger.PushLog(log)
		return
	}

	// file events
	target := esFileTarget(evType, evBody)
	if target == "" || actingExe == "" {
		return
	}
	p := pidMap[pid]
	log := mon.newESLog("File", target, esFileData(evType, evBody), pid, ppid, uid, pidVersion)
	log.ProcessName = actingExe
	log.ParentProcessName = pidExe(pidMap, ppid)
	log.TTY = actingTTY
	log.ExecEvent.ExecutableName = filepath.Base(actingExe)
	if p != nil {
		log.Source = strings.TrimSpace(p.ExePath + " " + strings.Join(argsTail(p.Args), " "))
		log.Cwd = withTrailingSlash(p.Cwd)
	} else {
		log.Source = actingExe
		log.Cwd = "/"
	}
	log.OID = esFileOID(evType, evBody)
	setHashes(&log, actingHash, pidHash(pidMap, ppid))
	mon.Logger.PushLog(log)
}

// newESLog builds a host-scope tp.Log skeleton for an event that has already
// occurred (Result is always "Passed").
func (mon *SystemMonitor) newESLog(operation, resource, data string, pid, ppid, uid, pidVersion int32) tp.Log {
	ts, tstr := kl.GetDateTimeNow()
	log := tp.Log{
		Timestamp:   ts,
		UpdatedTime: tstr,
		HostPID:     pid,
		HostPPID:    ppid,
		PID:         pid,
		PPID:        ppid,
		UID:         uid,
		Operation:   operation,
		Resource:    resource,
		Data:        data,
		Result:      "Passed",
	}
	log.ExecEvent.ExecID = fmt.Sprintf("%d.%d", pid, pidVersion)
	return log
}

// --- extraction helpers -----------------------------------------------------

func withTrailingSlash(p string) string {
	if p == "" {
		return "/"
	}
	return strings.TrimRight(p, "/") + "/"
}

func argsTail(args []string) []string {
	if len(args) <= 1 {
		return nil
	}
	return args[1:]
}

func pidExe(pidMap map[int32]*esProc, pid int32) string {
	if p := pidMap[pid]; p != nil {
		return p.ExePath
	}
	return ""
}

func pidHash(pidMap map[int32]*esProc, pid int32) string {
	if p := pidMap[pid]; p != nil {
		return p.CDHash
	}
	return ""
}

func setHashes(log *tp.Log, processHash, parentHash string) {
	log.ProcessHash = processHash
	log.ParentHash = parentHash
	if processHash != "" || parentHash != "" {
		log.HashAlgo = "cdhash"
	}
}

// esFileTarget extracts the affected path from a file event body.
func esFileTarget(evType string, b map[string]any) string {
	switch evType {
	case "open":
		return digStr(b, "file", "path")
	case "unlink", "truncate", "setmode", "setowner", "setflags", "link", "clone":
		if p := digStr(b, "target", "path"); p != "" {
			return p
		}
		return digStr(b, "file", "path")
	case "rename":
		return digStr(b, "source", "path")
	case "create":
		if p := digStr(b, "destination", "existing_file", "path"); p != "" {
			return p
		}
		dir := digStr(b, "destination", "new_path", "dir", "path")
		name := digStr(b, "destination", "new_path", "filename")
		if dir != "" {
			return strings.TrimRight(dir, "/") + "/" + name
		}
	}
	return ""
}

// esFileOID extracts the owner uid of the affected inode.
func esFileOID(evType string, b map[string]any) int32 {
	switch evType {
	case "open":
		return digInt(b, "file", "stat", "st_uid")
	case "rename":
		return digInt(b, "source", "stat", "st_uid")
	case "create":
		if u := digInt(b, "destination", "existing_file", "stat", "st_uid"); u != 0 {
			return u
		}
		return digInt(b, "destination", "new_path", "dir", "stat", "st_uid")
	default:
		return digInt(b, "target", "stat", "st_uid")
	}
}

// esFileData builds the `key=value` Data string; the feeder derives EventData from it.
func esFileData(evType string, b map[string]any) string {
	switch evType {
	case "open":
		return "syscall=open flags=" + esOpenFlags(digInt(b, "fflag"))
	case "setmode":
		return fmt.Sprintf("syscall=chmod mode=%04o", uint32(digInt(b, "mode")))
	case "setowner":
		return fmt.Sprintf("syscall=chown userid=%d group=%d", digInt(b, "uid"), digInt(b, "gid"))
	case "unlink":
		return "syscall=unlink"
	case "rename":
		return "syscall=rename"
	case "truncate":
		return "syscall=truncate"
	case "create":
		return "syscall=create"
	default:
		return "syscall=" + evType
	}
}

// esSessionFields maps a session/login/auth event body to the (resource, source,
// data) triplet consumed by newESLog. data always starts with "syscall=SYS_<NAME>"
// - the exact token shape feeder/policyMatcher.go's "Syscall" operation case
// already parses for Linux syscall auditing (see monitor/logUpdate.go) - so these
// events become ordinary matchSyscalls rules, e.g. `syscall: ["openssh_login"]`.
// source is the acting identity (username) so a `fromSource: [{path: "<user>"}]`
// rule can filter by who. Free-text fields (sudo's command, su's argv) are kept
// only in resource, never appended to data, since data is parsed as
// space-separated key=value tokens and would otherwise corrupt that parse.
func esSessionFields(evType string, b map[string]any) (resource, source, data string) {
	extra := ""
	switch evType {
	case "openssh_login":
		user, addr := digStr(b, "username"), digStr(b, "source_address")
		resource, source = user+"@"+addr, user
		extra = fmt.Sprintf("result=%s source=%s user=%s", successWord(digBool(b, "success")), addr, user)
	case "openssh_logout":
		user, addr := digStr(b, "username"), digStr(b, "source_address")
		resource, source = user+"@"+addr, user
		extra = fmt.Sprintf("source=%s user=%s", addr, user)
	case "login_login":
		user := digStr(b, "username")
		resource, source = user, user
		extra = fmt.Sprintf("result=%s user=%s", successWord(digBool(b, "success")), user)
	case "login_logout":
		user := digStr(b, "username")
		resource, source = user, user
		extra = "user=" + user
	case "lw_session_login", "lw_session_logout", "lw_session_lock", "lw_session_unlock":
		user := digStr(b, "username")
		resource, source = user, user
		extra = fmt.Sprintf("user=%s session=%d", user, digInt(b, "graphical_session_id"))
	case "screensharing_attach":
		viewer, addr, user := digStr(b, "viewer_appleid"), digStr(b, "source_address"), digStr(b, "session_username")
		resource, source = user+" via "+viewer, user
		extra = fmt.Sprintf("result=%s viewer=%s source=%s user=%s", successWord(digBool(b, "success")), viewer, addr, user)
	case "screensharing_detach":
		viewer, addr := digStr(b, "viewer_appleid"), digStr(b, "source_address")
		resource = viewer
		extra = fmt.Sprintf("viewer=%s source=%s", viewer, addr)
	case "su":
		from, to := digStr(b, "from_username"), digStr(b, "to_username")
		resource, source = from+"->"+to, from
		extra = fmt.Sprintf("result=%s from=%s to=%s", successWord(digBool(b, "success")), from, to)
	case "sudo":
		from, to, cmd := digStr(b, "from_username"), digStr(b, "to_username"), digStr(b, "command")
		resource = cmd
		if resource == "" {
			resource = from + "->" + to
		}
		source = from
		extra = fmt.Sprintf("result=%s from=%s to=%s", successWord(digBool(b, "success")), from, to)
	case "authentication":
		resource = "authentication"
		extra = fmt.Sprintf("result=%s type=%s", successWord(digBool(b, "success")), digStrOrInt(b, "type"))
	}
	data = "syscall=SYS_" + strings.ToUpper(evType)
	if extra != "" {
		data += " " + extra
	}
	return resource, source, data
}

func successWord(ok bool) string {
	if ok {
		return "success"
	}
	return "failure"
}

// esOpenFlags decodes the Endpoint Security `open` event fflag mask to `O_*`
// tokens. Per <EndpointSecurity/ESMessage.h>, es_event_open_t.fflag is "the mask
// as applied by the kernel, not as represented by typical open(2) oflag values" —
// the access mode is FREAD/FWRITE (i.e. O_RDONLY+1), NOT O_RDONLY/O_WRONLY/O_RDWR.
// So a read-only open is FREAD(0x1) with FWRITE(0x2) clear; the raw 0x0 O_RDONLY
// value never appears. The feeder's readOnly matcher keys on the literal
// "O_RDONLY", so getting this wrong makes every open look like a write.
func esOpenFlags(f int32) string {
	const (
		fread  = 0x0001 // FREAD
		fwrite = 0x0002 // FWRITE
	)
	var parts []string
	switch {
	case f&fwrite != 0 && f&fread != 0:
		parts = append(parts, "O_RDWR")
	case f&fwrite != 0:
		parts = append(parts, "O_WRONLY")
	default:
		parts = append(parts, "O_RDONLY")
	}
	// Non-accmode O_* bits keep their open(2) values in the FFLAG mask.
	for _, fl := range []struct {
		bit  int32
		name string
	}{
		{0x0008, "O_APPEND"},
		{0x0200, "O_CREAT"},
		{0x0400, "O_TRUNC"},
		{0x0800, "O_EXCL"},
	} {
		if f&fl.bit != 0 {
			parts = append(parts, fl.name)
		}
	}
	return strings.Join(parts, "|")
}

// dig walks a nested map[string]any by successive keys.
func dig(m map[string]any, keys ...string) any {
	var cur any = m
	for _, k := range keys {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = mm[k]
	}
	return cur
}

func digStr(m map[string]any, keys ...string) string {
	s, _ := dig(m, keys...).(string)
	return s
}

func digInt(m map[string]any, keys ...string) int32 {
	switch v := dig(m, keys...).(type) {
	case float64:
		return int32(v)
	case string:
		n, _ := strconv.Atoi(v)
		return int32(n)
	}
	return 0
}

func digBool(m map[string]any, keys ...string) bool {
	b, _ := dig(m, keys...).(bool)
	return b
}

// digStrOrInt reads a field that may render as either a string or a number
// (an enum, across macOS releases) and returns it as a string either way.
func digStrOrInt(m map[string]any, keys ...string) string {
	if s := digStr(m, keys...); s != "" {
		return s
	}
	if n := digInt(m, keys...); n != 0 {
		return strconv.Itoa(int(n))
	}
	return ""
}

func digStrSlice(m map[string]any, keys ...string) []string {
	arr, _ := dig(m, keys...).([]any)
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// digCDHash returns a lowercase-hex cdhash. eslogger renders es_cdhash_t either as
// a hex string or as an array of byte values depending on the macOS release.
func digCDHash(m map[string]any, keys ...string) string {
	switch v := dig(m, keys...).(type) {
	case string:
		return strings.ToLower(strings.TrimPrefix(v, "0x"))
	case []any:
		b := make([]byte, 0, len(v))
		for _, e := range v {
			f, ok := e.(float64)
			if !ok {
				return ""
			}
			b = append(b, byte(int(f)))
		}
		return hex.EncodeToString(b)
	}
	return ""
}
