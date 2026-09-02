// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

//go:build !darwin

package feeder

// platformUsernameLookup has no platform-specific fallback outside macOS; the
// stdlib os/user.LookupId path in GetUsername is authoritative.
func platformUsernameLookup(uid uint32) (string, bool) {
	return "", false
}
