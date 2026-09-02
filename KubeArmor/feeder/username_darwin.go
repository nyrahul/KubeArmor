// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

//go:build darwin

package feeder

import (
	"context"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// platformUsernameLookup resolves a uid to a username on macOS. With
// CGO_ENABLED=0, os/user.LookupId only reads /etc/passwd, which on macOS holds
// only system accounts; real users live in Directory Services. `id -nu <uid>`
// consults Directory Services and works for both.
func platformUsernameLookup(uid uint32) (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "id", "-nu", strconv.FormatUint(uint64(uid), 10)).Output() // #nosec G204 -- fixed args, numeric uid
	if err != nil {
		return "", false
	}
	name := strings.TrimSpace(string(out))
	if name == "" {
		return "", false
	}
	return name, true
}
