// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

//go:build !darwin

package monitor

// InitESLogger is a no-op on non-macOS platforms. On macOS it drives the
// Apple `eslogger` telemetry source (see esmonitor_darwin.go).
func (mon *SystemMonitor) InitESLogger() {}
