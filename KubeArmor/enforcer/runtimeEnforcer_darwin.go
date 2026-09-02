// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

//go:build darwin

package enforcer

import (
	"strings"

	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	es "github.com/kubearmor/KubeArmor/KubeArmor/enforcer/esenforcer"
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	mon "github.com/kubearmor/KubeArmor/KubeArmor/monitor"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// NewRuntimeEnforcer Function
//
// macOS has no LSM securityfs; the only supported host enforcer is Apple Endpoint
// Security. `-lsm` preference order still applies, but falls back to
// AppleEndpointSecurity when nothing in the order is available.
func NewRuntimeEnforcer(node tp.Node, pinpath string, logger *fd.Feeder, monitor *mon.SystemMonitor) *RuntimeEnforcer {
	re := &RuntimeEnforcer{}
	re.Logger = logger

	availablelsms := []string{"AppleEndpointSecurity"}
	lsms := []string{}
	if es.Available() {
		lsms = append(lsms, "AppleEndpointSecurity")
	}

	re.Logger.Printf("Supported enforcers: %s", strings.Join(lsms, ","))

	return selectLsm(re, cfg.GlobalCfg.LsmOrder, availablelsms, lsms, node, pinpath, logger, monitor)
}
