// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

// Package enforcer is responsible for setting up and handling policy updates for supported enforcers including AppArmor, SELinux and BPFLSM
package enforcer

import (
	"fmt"

	cle "github.com/cilium/ebpf"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	be "github.com/kubearmor/KubeArmor/KubeArmor/enforcer/bpflsm"
	es "github.com/kubearmor/KubeArmor/KubeArmor/enforcer/esenforcer"
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	mon "github.com/kubearmor/KubeArmor/KubeArmor/monitor"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// RuntimeEnforcer Structure
type RuntimeEnforcer struct {
	// logger
	Logger *fd.Feeder

	// LSM type
	EnforcerType string

	// LSM - BPFLSM
	bpfEnforcer *be.BPFEnforcer

	// LSM - AppArmor
	appArmorEnforcer *AppArmorEnforcer

	// LSM - SELinux
	seLinuxEnforcer *SELinuxEnforcer

	// macOS - Apple Endpoint Security
	esEnforcer *es.ESEnforcer
}

// selectLsm Function
func selectLsm(re *RuntimeEnforcer, lsmOrder, availablelsms, supportedlsm []string, node tp.Node, pinpath string, logger *fd.Feeder, monitor *mon.SystemMonitor) *RuntimeEnforcer {
	var err error
	var lsm string

lsmselection:
	//check lsm preference order
	if len(lsmOrder) != 0 {
		lsm = lsmOrder[0]
		lsmOrder = lsmOrder[1:]
		if kl.ContainsElement(supportedlsm, lsm) && kl.ContainsElement(availablelsms, lsm) {
			goto lsmdispatch
		}
		goto lsmselection
	}

	// fallback to available lsms order
	if len(availablelsms) != 0 {
		lsm = availablelsms[0]
		availablelsms = availablelsms[1:]
		if kl.ContainsElement(supportedlsm, lsm) {
			goto lsmdispatch
		}
		goto lsmselection
	}

	goto nil

lsmdispatch:
	switch lsm {
	case "bpf":
		goto bpf
	case "apparmor":
		goto apparmor
	case "selinux":
		goto selinux
	case "AppleEndpointSecurity":
		goto appleendpointsecurity
	default:
		goto lsmselection
	}

selinux:
	if !kl.IsInK8sCluster() {
		re.seLinuxEnforcer = NewSELinuxEnforcer(node, logger)
		if re.seLinuxEnforcer != nil {
			re.Logger.Print("Initialized SELinux Enforcer")
			re.EnforcerType = "SELinux"
			logger.UpdateEnforcer(re.EnforcerType)
			return re
		}
	}
	goto lsmselection

apparmor:
	re.appArmorEnforcer = NewAppArmorEnforcer(node, logger)
	if re.appArmorEnforcer != nil {
		re.Logger.Print("Initialized AppArmor Enforcer")
		re.EnforcerType = "AppArmor"
		logger.UpdateEnforcer(re.EnforcerType)
		return re
	}
	goto lsmselection

bpf:
	re.bpfEnforcer, err = be.NewBPFEnforcer(node, pinpath, logger, monitor)
	if re.bpfEnforcer != nil {
		if err != nil {
			re.Logger.Print("Error Initialising BPF-LSM Enforcer, Cleaning Up")
			if err := re.bpfEnforcer.DestroyBPFEnforcer(); err != nil {
				re.Logger.Err(err.Error())
			} else {
				re.Logger.Print("Destroyed BPF-LSM Enforcer")
			}
			goto lsmselection
		}
		re.Logger.Print("Initialized BPF-LSM Enforcer")
		re.EnforcerType = "BPFLSM"
		// Tell System Monitor that BPF LSM got your back, so it's okay to take rest and do less work
		if err := monitor.BpfConfigMap.Update(uint32(2), uint32(1), cle.UpdateAny); err != nil {
			re.Logger.Warnf("Error Updating System Monitor Config Map to notify it about usage of BPF LSM Enforcer : %s", err.Error())
		}
		logger.UpdateEnforcer(re.EnforcerType)
		return re
	}
	goto lsmselection

appleendpointsecurity:
	re.esEnforcer, err = es.NewESEnforcer(node, logger)
	if re.esEnforcer != nil {
		if err != nil {
			re.Logger.Print("Error Initialising Apple Endpoint Security Enforcer, Cleaning Up")
			if derr := re.esEnforcer.DestroyESEnforcer(); derr != nil {
				re.Logger.Err(derr.Error())
			}
			re.esEnforcer = nil
			goto lsmselection
		}
		re.Logger.Print("Initialized Apple Endpoint Security Enforcer")
		re.EnforcerType = "AppleEndpointSecurity"
		logger.UpdateEnforcer(re.EnforcerType)
		return re
	}
	goto lsmselection

nil:
	return nil
}

// RegisterContainer registers container identifiers to BPFEnforcer Map
func (re *RuntimeEnforcer) RegisterContainer(containerID string, pidns, mntns uint32) {
	// skip if runtime enforcer is not active
	if re == nil {
		return
	}

	if re.EnforcerType == "BPFLSM" {
		re.bpfEnforcer.AddContainerIDToMap(containerID, pidns, mntns)
	}
}

// UnregisterContainer removes container identifiers from BPFEnforcer Map
func (re *RuntimeEnforcer) UnregisterContainer(containerID string) {
	// skip if runtime enforcer is not active
	if re == nil {
		return
	}

	if re.EnforcerType == "BPFLSM" {
		re.bpfEnforcer.DeleteContainerIDFromMap(containerID)
	}
}

// UpdateAppArmorProfiles Function
func (re *RuntimeEnforcer) UpdateAppArmorProfiles(podName string, action string, profiles map[string]string, privilegedProfiles map[string]struct{}) {
	// skip if runtime enforcer is not active
	if re == nil {
		return
	}

	if re.EnforcerType == "AppArmor" {
		for _, profile := range profiles {
			if profile == "unconfined" {
				continue
			}

			_, privileged := privilegedProfiles[profile]

			if action == "ADDED" {
				re.appArmorEnforcer.RegisterAppArmorProfile(podName, profile, privileged)
			} else if action == "DELETED" {
				re.appArmorEnforcer.UnregisterAppArmorProfile(podName, profile, privileged)
			}
		}
	}
}

// UpdateSecurityPolicies Function
func (re *RuntimeEnforcer) UpdateSecurityPolicies(endPoint tp.EndPoint) {
	// skip if runtime enforcer is not active
	if re == nil {
		return
	}

	if re.EnforcerType == "BPFLSM" {
		re.bpfEnforcer.UpdateSecurityPolicies(endPoint)
	} else if re.EnforcerType == "AppArmor" {
		re.appArmorEnforcer.UpdateSecurityPolicies(endPoint)
	} else if re.EnforcerType == "AppleEndpointSecurity" {
		re.esEnforcer.UpdateSecurityPolicies(endPoint)
	}
}

// UpdateHostSecurityPolicies Function
func (re *RuntimeEnforcer) UpdateHostSecurityPolicies(secPolicies []tp.HostSecurityPolicy) {
	// skip if runtime enforcer is not active
	if re == nil {
		return
	}

	if re.EnforcerType == "BPFLSM" {
		re.bpfEnforcer.UpdateHostSecurityPolicies(secPolicies)
	} else if re.EnforcerType == "AppArmor" {
		re.appArmorEnforcer.UpdateHostSecurityPolicies(secPolicies)
	} else if re.EnforcerType == "SELinux" {
		re.seLinuxEnforcer.UpdateHostSecurityPolicies(secPolicies)
	} else if re.EnforcerType == "AppleEndpointSecurity" {
		re.esEnforcer.UpdateHostSecurityPolicies(secPolicies)
	}
}

// DestroyRuntimeEnforcer Function
func (re *RuntimeEnforcer) DestroyRuntimeEnforcer() error {
	// skip if runtime enforcer is not active
	if re == nil {
		return nil
	}

	errorLSM := false

	if re.EnforcerType == "BPFLSM" {
		if re.bpfEnforcer != nil {
			if err := re.bpfEnforcer.DestroyBPFEnforcer(); err != nil {
				re.Logger.Err(err.Error())
				errorLSM = true
			} else {
				re.Logger.Print("Destroyed BPF-LSM Enforcer")
			}
		}
	} else if re.EnforcerType == "AppArmor" {
		if re.appArmorEnforcer != nil {
			if err := re.appArmorEnforcer.DestroyAppArmorEnforcer(); err != nil {
				re.Logger.Err(err.Error())
				errorLSM = true
			} else {
				re.Logger.Print("Destroyed AppArmor Enforcer")
			}
		}
	} else if re.EnforcerType == "SELinux" {
		if re.seLinuxEnforcer != nil {
			if err := re.seLinuxEnforcer.DestroySELinuxEnforcer(); err != nil {
				re.Logger.Err(err.Error())
				errorLSM = true
			} else {
				re.Logger.Print("Destroyed SELinux Enforcer")
			}
		}
	} else if re.EnforcerType == "AppleEndpointSecurity" {
		if re.esEnforcer != nil {
			if err := re.esEnforcer.DestroyESEnforcer(); err != nil {
				re.Logger.Err(err.Error())
				errorLSM = true
			} else {
				re.Logger.Print("Destroyed Apple Endpoint Security Enforcer")
			}
		}
	}

	if errorLSM {
		return fmt.Errorf("failed to destroy RuntimeEnforcer (%s)", re.EnforcerType)
	}

	// Reset Enforcer to nil if no errors during clean up
	re = nil
	return nil
}
