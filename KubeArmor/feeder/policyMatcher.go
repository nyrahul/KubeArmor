package feeder

import (
	"regexp"
	"strconv"
	"strings"

	kl "github.com/accuknox/KubeArmor/KubeArmor/common"
	tp "github.com/accuknox/KubeArmor/KubeArmor/types"
)

// ======================= //
// == Security Policies == //
// ======================= //

// getProtocolFromName Function
func getProtocolFromName(proto string) string {
	switch strings.ToLower(proto) {
	case "tcp":
		return "type=SOCK_STREAM"
	case "udp":
		return "type=SOCK_DGRAM"
	case "icmp":
		return "type=SOCK_RAW protocol=1"
	default:
		return ""
	}
}

// getOperationAndCapabilityFromName
func getOperationAndCapabilityFromName(capName string) (op, cap string) {
	switch strings.ToLower(capName) {
	case "net_raw":
		op = "Network"
		cap = "type=SOCK_RAW protocol=1"
	default:
		return "", ""
	}

	return op, cap
}

// newMatchPolicy Function
func (fd *Feeder) newMatchPolicy(policyEnabled int, policyName, src string, mp interface{}) tp.MatchPolicy {
	match := tp.MatchPolicy{
		PolicyName: policyName,
		Source:     src,
	}

	if ppt, ok := mp.(tp.ProcessPathType); ok {
		match.Severity = strconv.Itoa(ppt.Severity)
		match.Tags = ppt.Tags
		match.Message = ppt.Message

		match.Operation = "Process"
		match.Resource = ppt.Path

		if policyEnabled == tp.KubeArmorPolicyAudited && strings.HasPrefix(ppt.Action, "Block") {
			match.Action = "Audit (" + ppt.Action + ")"
		} else {
			match.Action = ppt.Action
		}
	} else if pdt, ok := mp.(tp.ProcessDirectoryType); ok {
		match.Severity = strconv.Itoa(pdt.Severity)
		match.Tags = pdt.Tags
		match.Message = pdt.Message

		match.Operation = "Process"
		match.Resource = pdt.Directory

		if policyEnabled == tp.KubeArmorPolicyAudited && strings.HasPrefix(pdt.Action, "Block") {
			match.Action = "Audit (" + pdt.Action + ")"
		} else {
			match.Action = pdt.Action
		}
	} else if fpt, ok := mp.(tp.FilePathType); ok {
		match.Severity = strconv.Itoa(fpt.Severity)
		match.Tags = fpt.Tags
		match.Message = fpt.Message

		match.Operation = "File"
		match.Resource = fpt.Path

		if policyEnabled == tp.KubeArmorPolicyAudited && strings.HasPrefix(fpt.Action, "Block") {
			match.Action = "Audit (" + fpt.Action + ")"
		} else {
			match.Action = fpt.Action
		}
	} else if fdt, ok := mp.(tp.FileDirectoryType); ok {
		match.Severity = strconv.Itoa(fdt.Severity)
		match.Tags = fdt.Tags
		match.Message = fdt.Message

		match.Operation = "File"
		match.Resource = fdt.Directory

		if policyEnabled == tp.KubeArmorPolicyAudited && strings.HasPrefix(fdt.Action, "Block") {
			match.Action = "Audit (" + fdt.Action + ")"
		} else {
			match.Action = fdt.Action
		}
	} else if ppt, ok := mp.(tp.ProcessPatternType); ok {
		match.Severity = strconv.Itoa(ppt.Severity)
		match.Tags = ppt.Tags
		match.Message = ppt.Message

		match.Operation = "Process"
		match.Resource = ppt.Pattern

		if policyEnabled == tp.KubeArmorPolicyAudited && strings.HasPrefix(ppt.Action, "Block") {
			match.Action = "Audit (" + ppt.Action + ")"
		} else {
			match.Action = ppt.Action
		}
	} else if fpt, ok := mp.(tp.FilePatternType); ok {
		match.Severity = strconv.Itoa(fpt.Severity)
		match.Tags = fpt.Tags
		match.Message = fpt.Message
		match.Operation = "File"
		match.Resource = fpt.Pattern

		if policyEnabled == tp.KubeArmorPolicyAudited && strings.HasPrefix(fpt.Action, "Block") {
			match.Action = "Audit (" + fpt.Action + ")"
		} else {
			match.Action = fpt.Action
		}
	} else if npt, ok := mp.(tp.NetworkProtocolType); ok {
		match.Severity = strconv.Itoa(npt.Severity)
		match.Tags = npt.Tags
		match.Message = npt.Message

		match.Operation = "Network"
		match.Resource = getProtocolFromName(npt.Protocol)

		if policyEnabled == tp.KubeArmorPolicyAudited && strings.HasPrefix(npt.Action, "Block") {
			match.Action = "Audit (" + npt.Action + ")"
		} else if policyEnabled == tp.KubeArmorPolicyEnabled && fd.IsGKE && strings.HasPrefix(npt.Action, "Block") {
			match.Action = "Audit (" + npt.Action + ")"
		} else {
			match.Action = npt.Action
		}
	} else if cct, ok := mp.(tp.CapabilitiesCapabilityType); ok {
		match.Severity = strconv.Itoa(cct.Severity)
		match.Tags = cct.Tags
		match.Message = cct.Message

		op, cap := getOperationAndCapabilityFromName(cct.Capability)

		match.Operation = op
		match.Resource = cap

		if policyEnabled == tp.KubeArmorPolicyAudited && strings.HasPrefix(cct.Action, "Block") {
			match.Action = "Audit (" + cct.Action + ")"
		} else {
			match.Action = cct.Action
		}
	} else {
		return tp.MatchPolicy{}
	}

	return match
}

// UpdateSecurityPolicies Function
func (fd *Feeder) UpdateSecurityPolicies(action string, conGroup tp.ContainerGroup) {
	name := conGroup.NamespaceName + "_" + conGroup.ContainerGroupName

	if action == "DELETED" {
		delete(fd.SecurityPolicies, name)
		return
	}

	// ADDED | MODIFIED
	matches := tp.MatchPolicies{}

	for _, secPolicy := range conGroup.SecurityPolicies {
		policyName := secPolicy.Metadata["policyName"]

		if len(secPolicy.Spec.AppArmor) > 0 {
			match := tp.MatchPolicy{}

			match.PolicyName = policyName
			match.Native = true

			matches.Policies = append(matches.Policies, match)
			continue
		}

		for _, path := range secPolicy.Spec.Process.MatchPaths {
			fromSource := ""

			if len(path.FromSource) == 0 {
				match := fd.newMatchPolicy(conGroup.PolicyEnabled, policyName, fromSource, path)
				matches.Policies = append(matches.Policies, match)
				continue
			}

			for _, src := range path.FromSource {
				if len(src.Path) > 0 {
					fromSource = src.Path
				} else if len(src.Directory) > 0 {
					fromSource = src.Directory
				} else {
					continue
				}

				match := fd.newMatchPolicy(conGroup.PolicyEnabled, policyName, fromSource, path)
				matches.Policies = append(matches.Policies, match)
			}
		}

		for _, dir := range secPolicy.Spec.Process.MatchDirectories {
			fromSource := ""

			if len(dir.FromSource) == 0 {
				match := fd.newMatchPolicy(conGroup.PolicyEnabled, policyName, fromSource, dir)
				matches.Policies = append(matches.Policies, match)
				continue
			}

			for _, src := range dir.FromSource {
				if len(src.Path) > 0 {
					fromSource = src.Path
				} else if len(src.Directory) > 0 {
					fromSource = src.Directory
				} else {
					continue
				}

				match := fd.newMatchPolicy(conGroup.PolicyEnabled, policyName, fromSource, dir)
				matches.Policies = append(matches.Policies, match)
			}
		}

		for _, patt := range secPolicy.Spec.Process.MatchPatterns {
			if len(patt.Pattern) == 0 {
				continue
			}

			regexpComp, err := regexp.Compile(patt.Pattern)
			if err != nil {
				continue
			}

			fromSource := ""

			match := fd.newMatchPolicy(conGroup.PolicyEnabled, policyName, fromSource, patt)
			match.Regexp = regexpComp
			matches.Policies = append(matches.Policies, match)
		}

		for _, path := range secPolicy.Spec.File.MatchPaths {
			fromSource := ""

			if len(path.FromSource) == 0 {
				match := fd.newMatchPolicy(conGroup.PolicyEnabled, policyName, fromSource, path)
				matches.Policies = append(matches.Policies, match)
				continue
			}

			for _, src := range path.FromSource {
				if len(src.Path) > 0 {
					fromSource = src.Path
				} else if len(src.Directory) > 0 {
					fromSource = src.Directory
				} else {
					continue
				}

				match := fd.newMatchPolicy(conGroup.PolicyEnabled, policyName, fromSource, path)
				matches.Policies = append(matches.Policies, match)
			}
		}

		for _, dir := range secPolicy.Spec.File.MatchDirectories {
			fromSource := ""

			if len(dir.FromSource) == 0 {
				match := fd.newMatchPolicy(conGroup.PolicyEnabled, policyName, fromSource, dir)
				matches.Policies = append(matches.Policies, match)
				continue
			}

			for _, src := range dir.FromSource {
				if len(src.Path) > 0 {
					fromSource = src.Path
				} else if len(src.Directory) > 0 {
					fromSource = src.Directory
				} else {
					continue
				}

				match := fd.newMatchPolicy(conGroup.PolicyEnabled, policyName, fromSource, dir)
				matches.Policies = append(matches.Policies, match)
			}
		}

		for _, patt := range secPolicy.Spec.File.MatchPatterns {
			if len(patt.Pattern) == 0 {
				continue
			}

			regexpComp, err := regexp.Compile(patt.Pattern)
			if err != nil {
				continue
			}

			fromSource := ""

			match := fd.newMatchPolicy(conGroup.PolicyEnabled, policyName, fromSource, patt)
			match.Regexp = regexpComp
			matches.Policies = append(matches.Policies, match)
		}

		for _, proto := range secPolicy.Spec.Network.MatchProtocols {
			if len(proto.Protocol) == 0 {
				continue
			}

			fromSource := ""

			if len(proto.FromSource) == 0 {
				match := fd.newMatchPolicy(conGroup.PolicyEnabled, policyName, fromSource, proto)
				if len(match.Resource) == 0 {
					continue
				}
				matches.Policies = append(matches.Policies, match)
				continue
			}

			for _, src := range proto.FromSource {
				if len(src.Path) > 0 {
					fromSource = src.Path
				} else if len(src.Directory) > 0 {
					fromSource = src.Directory
				} else {
					continue
				}

				match := fd.newMatchPolicy(conGroup.PolicyEnabled, policyName, fromSource, proto)
				if len(match.Resource) == 0 {
					continue
				}
				matches.Policies = append(matches.Policies, match)
			}

		}

		for _, cap := range secPolicy.Spec.Capabilities.MatchCapabilities {
			if len(cap.Capability) == 0 {
				continue
			}

			fromSource := ""

			if len(cap.FromSource) == 0 {
				match := fd.newMatchPolicy(conGroup.PolicyEnabled, policyName, fromSource, cap)
				if len(match.Resource) == 0 {
					continue
				}
				matches.Policies = append(matches.Policies, match)
				continue
			}

			for _, src := range cap.FromSource {
				if len(src.Path) > 0 {
					fromSource = src.Path
				} else if len(src.Directory) > 0 {
					fromSource = src.Directory
				} else {
					continue
				}

				match := fd.newMatchPolicy(conGroup.PolicyEnabled, policyName, fromSource, cap)
				if len(match.Resource) == 0 {
					continue
				}
				matches.Policies = append(matches.Policies, match)
			}

		}

		// for _, res := range secPolicy.Spec.Resource.MatchResources {
		// }
	}

	fd.SecurityPoliciesLock.Lock()
	fd.SecurityPolicies[name] = matches
	fd.SecurityPoliciesLock.Unlock()
}

// ============================ //
// == Host Security Policies == //
// ============================ //

// UpdateHostSecurityPolicies Function
func (fd *Feeder) UpdateHostSecurityPolicies(action string, secPolicies []tp.HostSecurityPolicy) {
	if action == "DELETED" {
		delete(fd.SecurityPolicies, fd.HostName)
		return
	}

	// ADDED | MODIFIED
	matches := tp.MatchPolicies{}

	for _, secPolicy := range secPolicies {
		policyName := secPolicy.Metadata["policyName"]

		if len(secPolicy.Spec.AppArmor) > 0 {
			match := tp.MatchPolicy{}

			match.PolicyName = policyName
			match.Native = true

			matches.Policies = append(matches.Policies, match)
			continue
		}

		for _, path := range secPolicy.Spec.Process.MatchPaths {
			fromSource := ""

			if len(path.FromSource) == 0 {
				match := fd.newMatchPolicy(fd.HostPolicyEnabled, policyName, fromSource, path)
				matches.Policies = append(matches.Policies, match)
				continue
			}

			for _, src := range path.FromSource {
				if len(src.Path) > 0 {
					fromSource = src.Path
				} else if len(src.Directory) > 0 {
					fromSource = src.Directory
				} else {
					continue
				}

				match := fd.newMatchPolicy(fd.HostPolicyEnabled, policyName, fromSource, path)
				matches.Policies = append(matches.Policies, match)
			}
		}

		for _, dir := range secPolicy.Spec.Process.MatchDirectories {
			fromSource := ""

			if len(dir.FromSource) == 0 {
				match := fd.newMatchPolicy(fd.HostPolicyEnabled, policyName, fromSource, dir)
				matches.Policies = append(matches.Policies, match)
				continue
			}

			for _, src := range dir.FromSource {
				if len(src.Path) > 0 {
					fromSource = src.Path
				} else if len(src.Directory) > 0 {
					fromSource = src.Directory
				} else {
					continue
				}

				match := fd.newMatchPolicy(fd.HostPolicyEnabled, policyName, fromSource, dir)
				matches.Policies = append(matches.Policies, match)
			}
		}

		for _, patt := range secPolicy.Spec.Process.MatchPatterns {
			if len(patt.Pattern) == 0 {
				continue
			}

			regexpComp, err := regexp.Compile(patt.Pattern)
			if err != nil {
				continue
			}

			fromSource := ""

			match := fd.newMatchPolicy(fd.HostPolicyEnabled, policyName, fromSource, patt)
			match.Regexp = regexpComp
			matches.Policies = append(matches.Policies, match)
		}

		for _, path := range secPolicy.Spec.File.MatchPaths {
			fromSource := ""

			if len(path.FromSource) == 0 {
				match := fd.newMatchPolicy(fd.HostPolicyEnabled, policyName, fromSource, path)
				matches.Policies = append(matches.Policies, match)
				continue
			}

			for _, src := range path.FromSource {
				if len(src.Path) > 0 {
					fromSource = src.Path
				} else if len(src.Directory) > 0 {
					fromSource = src.Directory
				} else {
					continue
				}

				match := fd.newMatchPolicy(fd.HostPolicyEnabled, policyName, fromSource, path)
				matches.Policies = append(matches.Policies, match)
			}
		}

		for _, dir := range secPolicy.Spec.File.MatchDirectories {
			fromSource := ""

			if len(dir.FromSource) == 0 {
				match := fd.newMatchPolicy(fd.HostPolicyEnabled, policyName, fromSource, dir)
				matches.Policies = append(matches.Policies, match)
				continue
			}

			for _, src := range dir.FromSource {
				if len(src.Path) > 0 {
					fromSource = src.Path
				} else if len(src.Directory) > 0 {
					fromSource = src.Directory
				} else {
					continue
				}

				match := fd.newMatchPolicy(fd.HostPolicyEnabled, policyName, fromSource, dir)
				matches.Policies = append(matches.Policies, match)
			}
		}

		for _, patt := range secPolicy.Spec.File.MatchPatterns {
			if len(patt.Pattern) == 0 {
				continue
			}

			regexpComp, err := regexp.Compile(patt.Pattern)
			if err != nil {
				continue
			}

			fromSource := ""

			match := fd.newMatchPolicy(fd.HostPolicyEnabled, policyName, fromSource, patt)
			match.Regexp = regexpComp
			matches.Policies = append(matches.Policies, match)
		}

		for _, proto := range secPolicy.Spec.Network.MatchProtocols {
			if len(proto.Protocol) == 0 {
				continue
			}

			fromSource := ""

			if len(proto.FromSource) == 0 {
				match := fd.newMatchPolicy(fd.HostPolicyEnabled, policyName, fromSource, proto)
				if len(match.Resource) == 0 {
					continue
				}
				matches.Policies = append(matches.Policies, match)
				continue
			}

			for _, src := range proto.FromSource {
				if len(src.Path) > 0 {
					fromSource = src.Path
				} else if len(src.Directory) > 0 {
					fromSource = src.Directory
				} else {
					continue
				}

				match := fd.newMatchPolicy(fd.HostPolicyEnabled, policyName, fromSource, proto)
				if len(match.Resource) == 0 {
					continue
				}
				matches.Policies = append(matches.Policies, match)
			}

		}

		for _, cap := range secPolicy.Spec.Capabilities.MatchCapabilities {
			if len(cap.Capability) == 0 {
				continue
			}

			fromSource := ""

			if len(cap.FromSource) == 0 {
				match := fd.newMatchPolicy(fd.HostPolicyEnabled, policyName, fromSource, cap)
				if len(match.Resource) == 0 {
					continue
				}
				matches.Policies = append(matches.Policies, match)
				continue
			}

			for _, src := range cap.FromSource {
				if len(src.Path) > 0 {
					fromSource = src.Path
				} else if len(src.Directory) > 0 {
					fromSource = src.Directory
				} else {
					continue
				}

				match := fd.newMatchPolicy(fd.HostPolicyEnabled, policyName, fromSource, cap)
				if len(match.Resource) == 0 {
					continue
				}
				matches.Policies = append(matches.Policies, match)
			}

		}
	}

	fd.SecurityPoliciesLock.Lock()
	fd.SecurityPolicies[fd.HostName] = matches
	fd.SecurityPoliciesLock.Unlock()
}

// ==================== //
// == Policy Matches == //
// ==================== //

// UpdateMatchedPolicy Function
func (fd *Feeder) UpdateMatchedPolicy(log tp.Log) tp.Log {
	allowProcPolicy := ""
	allowProcPolicySeverity := ""
	allowProcTags := []string{}
	allowProcMessage := ""

	allowFilePolicy := ""
	allowFilePolicySeverity := ""
	allowFileTags := []string{}
	allowFileMessage := ""

	allowNetworkPolicy := ""
	allowNetworkPolicySeverity := ""
	allowNetworkTags := []string{}
	allowNetworkMessage := ""

	mightBeNative := false

	if log.Result == "Passed" || log.Result == "Operation not permitted" || log.Result == "Permission denied" {
		fd.SecurityPoliciesLock.RLock()

		key := log.HostName

		if log.NamespaceName != "" && log.PodName != "" {
			key = log.NamespaceName + "_" + log.PodName
		}

		secPolicies := fd.SecurityPolicies[key].Policies
		for _, secPolicy := range secPolicies {
			if secPolicy.Native && log.Result != "Passed" {
				mightBeNative = true
				continue
			}

			if secPolicy.Source == "" || strings.Contains(secPolicy.Source, log.Source) {
				if secPolicy.Action == "Allow" || secPolicy.Action == "AllowWithAudit" {
					if secPolicy.Operation == "Process" {
						if allowProcPolicy == "" {
							allowProcPolicy = secPolicy.PolicyName
							allowProcPolicySeverity = secPolicy.Severity

							for _, tag := range secPolicy.Tags {
								if !kl.ContainsElement(allowProcTags, tag) {
									allowProcTags = append(allowProcTags, tag)
								}
							}

							allowProcMessage = secPolicy.Message
						} else if !strings.Contains(allowProcPolicy, secPolicy.PolicyName) {
							allowProcPolicy = allowProcPolicy + "," + secPolicy.PolicyName
							allowProcPolicySeverity = allowProcPolicySeverity + "," + secPolicy.Severity

							for _, tag := range secPolicy.Tags {
								if !kl.ContainsElement(allowProcTags, tag) {
									allowProcTags = append(allowProcTags, tag)
								}
							}

							allowProcMessage = allowProcMessage + "," + secPolicy.Message
						}
					} else if secPolicy.Operation == "File" {
						if allowFilePolicy == "" {
							allowFilePolicy = secPolicy.PolicyName
							allowFilePolicySeverity = secPolicy.Severity

							for _, tag := range secPolicy.Tags {
								if !kl.ContainsElement(allowFileTags, tag) {
									allowFileTags = append(allowFileTags, tag)
								}
							}

							allowFileMessage = secPolicy.Message
						} else if !strings.Contains(allowFilePolicy, secPolicy.PolicyName) {
							allowFilePolicy = allowFilePolicy + "," + secPolicy.PolicyName
							allowFilePolicySeverity = allowFilePolicySeverity + "," + secPolicy.Severity

							for _, tag := range secPolicy.Tags {
								if !kl.ContainsElement(allowFileTags, tag) {
									allowFileTags = append(allowFileTags, tag)
								}
							}

							allowFileMessage = allowFileMessage + "," + secPolicy.Message
						}
					} else if secPolicy.Operation == "Network" {
						if allowNetworkPolicy == "" {
							allowNetworkPolicy = secPolicy.PolicyName
							allowNetworkPolicySeverity = secPolicy.Severity

							for _, tag := range secPolicy.Tags {
								if !kl.ContainsElement(allowNetworkTags, tag) {
									allowNetworkTags = append(allowNetworkTags, tag)
								}
							}

							allowNetworkMessage = secPolicy.Message
						} else if !strings.Contains(allowNetworkPolicy, secPolicy.PolicyName) {
							allowNetworkPolicy = allowNetworkPolicy + "," + secPolicy.PolicyName
							allowNetworkPolicySeverity = allowNetworkPolicySeverity + "," + secPolicy.Severity

							for _, tag := range secPolicy.Tags {
								if !kl.ContainsElement(allowNetworkTags, tag) {
									allowNetworkTags = append(allowNetworkTags, tag)
								}
							}

							allowNetworkMessage = allowNetworkMessage + "," + secPolicy.Message
						}
					}
				}
			}

			switch log.Operation {
			case "Process", "File":
				if secPolicy.Operation == log.Operation {
					if strings.HasPrefix(log.Resource, secPolicy.Resource) {
						if secPolicy.Source != "" && strings.Contains(secPolicy.Source, log.Source) {
							log.PolicyName = secPolicy.PolicyName
							log.Severity = secPolicy.Severity

							if len(secPolicy.Tags) > 0 {
								log.Tags = strings.Join(secPolicy.Tags[:], ",")
							}

							if len(secPolicy.Message) > 0 {
								log.Message = secPolicy.Message
							}

							log.Type = "MatchedPolicy"
							log.Action = secPolicy.Action

							break
						} else if secPolicy.Source == "" {
							log.PolicyName = secPolicy.PolicyName
							log.Severity = secPolicy.Severity

							if len(secPolicy.Tags) > 0 {
								log.Tags = strings.Join(secPolicy.Tags[:], ",")
							}

							if len(secPolicy.Message) > 0 {
								log.Message = secPolicy.Message
							}

							log.Type = "MatchedPolicy"
							log.Action = secPolicy.Action

							break
						}
					}
				}
			case "Network":
				if secPolicy.Operation == log.Operation {
					if strings.Contains(log.Resource, secPolicy.Resource) {
						if secPolicy.Source != "" && strings.Contains(secPolicy.Source, log.Source) {
							log.PolicyName = secPolicy.PolicyName
							log.Severity = secPolicy.Severity

							if len(secPolicy.Tags) > 0 {
								log.Tags = strings.Join(secPolicy.Tags[:], ",")
							}

							if len(secPolicy.Message) > 0 {
								log.Message = secPolicy.Message
							}

							log.Type = "MatchedPolicy"
							log.Action = secPolicy.Action

							break
						} else if secPolicy.Source == "" {
							log.PolicyName = secPolicy.PolicyName
							log.Severity = secPolicy.Severity

							if len(secPolicy.Tags) > 0 {
								log.Tags = strings.Join(secPolicy.Tags[:], ",")
							}

							if len(secPolicy.Message) > 0 {
								log.Message = secPolicy.Message
							}

							log.Type = "MatchedPolicy"
							log.Action = secPolicy.Action

							break
						}
					}
				}
			}
		}

		fd.SecurityPoliciesLock.RUnlock()
	}

	if log.ContainerID != "" { // container
		if log.Type == "" {
			if log.Result != "Passed" {
				if log.Operation == "Process" && allowProcPolicy != "" {
					log.PolicyName = allowProcPolicy
					log.Severity = allowProcPolicySeverity

					if len(allowProcTags) > 0 {
						log.Tags = strings.Join(allowProcTags[:], ",")
					}

					if len(allowProcMessage) > 0 {
						log.Message = allowProcMessage
					}

					log.Type = "MatchedPolicy"
					log.Action = "Allow"

					return log

				} else if log.Operation == "File" && allowFilePolicy != "" {
					log.PolicyName = allowFilePolicy
					log.Severity = allowFilePolicySeverity

					if len(allowFileTags) > 0 {
						log.Tags = strings.Join(allowFileTags[:], ",")
					}

					if len(allowFileMessage) > 0 {
						log.Message = allowFileMessage
					}

					log.Type = "MatchedPolicy"
					log.Action = "Allow"

					return log

				} else if log.Operation == "Network" && allowNetworkPolicy != "" {
					log.PolicyName = allowNetworkPolicy
					log.Severity = allowNetworkPolicySeverity

					if len(allowNetworkTags) > 0 {
						log.Tags = strings.Join(allowNetworkTags[:], ",")
					}

					if len(allowNetworkMessage) > 0 {
						log.Message = allowNetworkMessage
					}

					log.Type = "MatchedPolicy"
					log.Action = "Allow"

					return log

				}

				if mightBeNative {
					log.PolicyName = "NativePolicy"

					log.Severity = "-"
					log.Tags = "-"
					log.Message = "KubeArmor detected a native policy violation"

					log.Type = "MatchedNativePolicy"
					log.Action = "Block"

					return log
				}

				// Failed operations
				if log.ProcessVisibilityEnabled && log.Operation == "Process" {
					log.Type = "ContainerLog"
					return log
				} else if log.FileVisibilityEnabled && log.Operation == "File" {
					log.Type = "ContainerLog"
					return log
				} else if log.NetworkVisibilityEnabled && log.Operation == "Network" {
					log.Type = "ContainerLog"
					return log
				} else if log.CapabilitiesVisibilityEnabled && log.Operation == "Capabilities" {
					log.Type = "ContainerLog"
					return log
				}
			} else { // Passed
				if log.Action == "Allow" {
					// use 'AllowWithAudit' to get the logs for allowed operations
					return tp.Log{}
				}

				// Passed operations
				if log.ProcessVisibilityEnabled && log.Operation == "Process" {
					log.Type = "ContainerLog"
					return log
				} else if log.FileVisibilityEnabled && log.Operation == "File" {
					log.Type = "ContainerLog"
					return log
				} else if log.NetworkVisibilityEnabled && log.Operation == "Network" {
					log.Type = "ContainerLog"
					return log
				} else if log.CapabilitiesVisibilityEnabled && log.Operation == "Capabilities" {
					log.Type = "ContainerLog"
					return log
				}
			}
		} else if log.Type == "MatchedPolicy" {
			// if log.Action == "Block" {
			// 	// use 'BlockWithAudit' to get the logs for blocked operations
			// 	return tp.Log{}
			// }

			return log
		}
	} else { // host
		if log.Type == "" {
			if log.Result != "Passed" {
				if log.Operation == "Process" && allowProcPolicy != "" {
					log.PolicyName = allowProcPolicy
					log.Severity = allowProcPolicySeverity

					if len(allowProcTags) > 0 {
						log.Tags = strings.Join(allowProcTags[:], ",")
					}

					if len(allowProcMessage) > 0 {
						log.Message = allowProcMessage
					}

					log.Type = "MatchedHostPolicy"
					log.Action = "Allow"

					return log

				} else if log.Operation == "File" && allowFilePolicy != "" {
					log.PolicyName = allowFilePolicy
					log.Severity = allowFilePolicySeverity

					if len(allowFileTags) > 0 {
						log.Tags = strings.Join(allowFileTags[:], ",")
					}

					if len(allowFileMessage) > 0 {
						log.Message = allowFileMessage
					}

					log.Type = "MatchedHostPolicy"
					log.Action = "Allow"

					return log

				} else if log.Operation == "Network" && allowNetworkPolicy != "" {
					log.PolicyName = allowNetworkPolicy
					log.Severity = allowNetworkPolicySeverity

					if len(allowNetworkTags) > 0 {
						log.Tags = strings.Join(allowNetworkTags[:], ",")
					}

					if len(allowNetworkMessage) > 0 {
						log.Message = allowNetworkMessage
					}

					log.Type = "MatchedHostPolicy"
					log.Action = "Allow"

					return log

				}

				if mightBeNative {
					log.PolicyName = "NativePolicy"

					log.Severity = "-"
					log.Tags = "-"
					log.Message = "KubeArmor detected a native policy violation"

					log.Type = "MatchedNativePolicy"
					log.Action = "Block"

					return log
				}
			} else {
				if log.Action == "Allow" {
					// use 'AllowWithAudit' to get the logs for allowed operations
					return tp.Log{}
				}
			}
		} else if log.Type == "MatchedPolicy" {
			// if log.Action == "Block" {
			// 	// use 'BlockWithAudit' to get the logs for blocked operations
			// 	return tp.Log{}
			// }

			log.Type = "MatchedHostPolicy"
			return log
		}
	}

	return tp.Log{}
}
