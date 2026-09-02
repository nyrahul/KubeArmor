// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

//go:build darwin

package esenforcer

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

// maxFrame bounds a single length-prefixed frame from the helper.
const maxFrame = 4 << 20 // 4 MiB

// writeFrame writes a 4-byte big-endian length prefix followed by payload.
func writeFrame(w io.Writer, payload []byte) error {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// readFrame reads one length-prefixed frame.
func readFrame(r *bufio.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > maxFrame {
		return nil, fmt.Errorf("es helper frame too large: %d bytes", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// esFrame is one JSON object sent by kubearmor-es-helper (helper -> daemon).
type esFrame struct {
	Kind string `json:"kind"` // HELLO | BLOCKED | UNAVAILABLE | PONG

	Version int    `json:"version,omitempty"`
	Reason  string `json:"reason,omitempty"`

	// BLOCKED
	Op        string   `json:"op,omitempty"` // Process | File
	PID       int32    `json:"pid,omitempty"`
	PPID      int32    `json:"ppid,omitempty"`
	EUID      int32    `json:"euid,omitempty"`
	Exe       string   `json:"exe,omitempty"`
	ParentExe string   `json:"parentExe,omitempty"`
	Target    string   `json:"target,omitempty"`
	Cwd       string   `json:"cwd,omitempty"`
	TTY       string   `json:"tty,omitempty"`
	Args      []string `json:"args,omitempty"`
	Data      string   `json:"data,omitempty"` // syscall=… [flags=…]
	Rule      string   `json:"rule,omitempty"`
	Severity  int      `json:"severity,omitempty"`
	Message   string   `json:"message,omitempty"`
	TS        int64    `json:"ts,omitempty"`
}

func parseFrame(b []byte) (esFrame, error) {
	var f esFrame
	err := json.Unmarshal(b, &f)
	return f, err
}
