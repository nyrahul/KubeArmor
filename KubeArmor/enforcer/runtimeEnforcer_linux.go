// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

//go:build linux

package enforcer

import (
	"os"
	"path/filepath"
	"strings"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	mon "github.com/kubearmor/KubeArmor/KubeArmor/monitor"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	probe "github.com/kubearmor/KubeArmor/KubeArmor/utils/bpflsmprobe"
)

// NewRuntimeEnforcer Function
func NewRuntimeEnforcer(node tp.Node, pinpath string, logger *fd.Feeder, monitor *mon.SystemMonitor) *RuntimeEnforcer {
	availablelsms := []string{"bpf", "selinux", "apparmor"}
	re := &RuntimeEnforcer{}
	re.Logger = logger

	lsms := []string{}

	lsmFile := []byte{}
	lsmPath := "/sys/kernel/security/lsm"

	if !kl.IsK8sLocal() {
		// mount securityfs
		if err := kl.RunCommandAndWaitWithErr("mount", []string{"-t", "securityfs", "securityfs", "/sys/kernel/security"}); err != nil {
			if _, err := os.Stat(filepath.Clean("/sys/kernel/security")); err != nil {
				re.Logger.Warnf("Failed to read /sys/kernel/security (%s)", err.Error())
				goto probeBPFLSM
			}
		}
	}

	if _, err := os.Stat(filepath.Clean(lsmPath)); err == nil {
		lsmFile, err = os.ReadFile(lsmPath)
		if err != nil {
			re.Logger.Warnf("Failed to read /sys/kernel/security/lsm (%s)", err.Error())
			goto probeBPFLSM
		}
	}

	lsms = strings.Split(string(lsmFile), ",")

probeBPFLSM:
	if !kl.ContainsElement(lsms, "bpf") {
		err := probe.CheckBPFLSMSupport()
		if err == nil {
			lsms = append(lsms, "bpf")
		} else {
			re.Logger.Warnf("BPF LSM not supported %s", err.Error())
		}
	}

	re.Logger.Printf("Supported LSMs: %s", strings.Join(lsms, ","))

	return selectLsm(re, cfg.GlobalCfg.LsmOrder, availablelsms, lsms, node, pinpath, logger, monitor)
}
