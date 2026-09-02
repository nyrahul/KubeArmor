// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

//go:build !darwin

// Package esenforcer is KubeArmor's macOS host enforcer. This file is a no-op stub
// so the rest of KubeArmor compiles on non-macOS platforms; the real implementation
// lives in esenforcer.go (//go:build darwin).
package esenforcer

import (
	"errors"

	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// EnforcerType is the RuntimeEnforcer discriminator for this backend.
const EnforcerType = "AppleEndpointSecurity"

// ESEnforcer is a no-op placeholder on non-macOS platforms.
type ESEnforcer struct{}

// Available reports that the Apple Endpoint Security enforcer is unavailable off macOS.
func Available() bool {
	return false
}

// Enforcing always reports false off macOS.
func (e *ESEnforcer) Enforcing() bool { return false }

// NewESEnforcer returns an error on non-macOS platforms.
func NewESEnforcer(node tp.Node, logger *fd.Feeder) (*ESEnforcer, error) {
	return nil, errors.New("Apple Endpoint Security enforcer is only available on macOS")
}

// DestroyESEnforcer is a no-op on non-macOS platforms.
func (e *ESEnforcer) DestroyESEnforcer() error { return nil }

// AddContainerIDToMap is a no-op on non-macOS platforms.
func (e *ESEnforcer) AddContainerIDToMap(containerID string, pidns, mntns uint32) {}

// DeleteContainerIDFromMap is a no-op on non-macOS platforms.
func (e *ESEnforcer) DeleteContainerIDFromMap(containerID string) {}

// UpdateSecurityPolicies is a no-op on non-macOS platforms.
func (e *ESEnforcer) UpdateSecurityPolicies(endPoint tp.EndPoint) {}

// UpdateHostSecurityPolicies is a no-op on non-macOS platforms.
func (e *ESEnforcer) UpdateHostSecurityPolicies(secPolicies []tp.HostSecurityPolicy) {}
