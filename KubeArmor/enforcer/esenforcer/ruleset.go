// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

//go:build darwin

package esenforcer

import (
	"fmt"
	"strings"

	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// esRule is one compiled Block rule pushed to kubearmor-es-helper. Operation is
// "process" (ES AUTH_EXEC) or "file" (ES AUTH_OPEN and the mutation events).
type esRule struct {
	Operation  string // process | file
	MatchType  string // path | dir | glob | execname
	Value      string
	Recursive  bool
	OwnerOnly  bool
	ReadOnly   bool
	FromSource []string
	Severity   int
	RuleName   string
	Message    string
}

// compileHostRules flattens the *Block* process and file rules of the host policy
// set, in the order KubeArmor's matcher scans them (per policy: MatchPaths ->
// MatchDirectories -> MatchPatterns; policies in slice order). Audit/Allow rules
// produce nothing for the helper: an audited/allowed operation proceeds and is
// reported via the eslogger path. Per-rule Severity / Message are already
// inherited onto each sub-rule by ParseAndUpdateHostSecurityPolicy.
func compileHostRules(secPolicies []tp.HostSecurityPolicy) []esRule {
	var rules []esRule

	for _, p := range secPolicies {
		name := p.Metadata["policyName"]

		proc := p.Spec.Process
		for _, mp := range proc.MatchPaths {
			if mp.Action != "Block" {
				continue
			}
			mt, val := "path", mp.Path
			if mp.ExecName != "" {
				mt, val = "execname", mp.ExecName
			}
			rules = append(rules, esRule{
				Operation:  "process",
				MatchType:  mt,
				Value:      val,
				OwnerOnly:  mp.OwnerOnly,
				FromSource: sourcePaths(mp.FromSource),
				Severity:   mp.Severity,
				RuleName:   name,
				Message:    mp.Message,
			})
		}
		for _, md := range proc.MatchDirectories {
			if md.Action != "Block" {
				continue
			}
			rules = append(rules, esRule{
				Operation:  "process",
				MatchType:  "dir",
				Value:      md.Directory,
				Recursive:  md.Recursive,
				OwnerOnly:  md.OwnerOnly,
				FromSource: sourcePaths(md.FromSource),
				Severity:   md.Severity,
				RuleName:   name,
				Message:    md.Message,
			})
		}
		for _, mpat := range proc.MatchPatterns {
			if mpat.Action != "Block" {
				continue
			}
			rules = append(rules, esRule{
				Operation: "process",
				MatchType: "glob",
				Value:     mpat.Pattern,
				OwnerOnly: mpat.OwnerOnly,
				Severity:  mpat.Severity,
				RuleName:  name,
				Message:   mpat.Message,
			})
		}

		file := p.Spec.File
		for _, mp := range file.MatchPaths {
			if mp.Action != "Block" {
				continue
			}
			rules = append(rules, esRule{
				Operation:  "file",
				MatchType:  "path",
				Value:      mp.Path,
				OwnerOnly:  mp.OwnerOnly,
				ReadOnly:   mp.ReadOnly,
				FromSource: sourcePaths(mp.FromSource),
				Severity:   mp.Severity,
				RuleName:   name,
				Message:    mp.Message,
			})
		}
		for _, md := range file.MatchDirectories {
			if md.Action != "Block" {
				continue
			}
			rules = append(rules, esRule{
				Operation:  "file",
				MatchType:  "dir",
				Value:      md.Directory,
				Recursive:  md.Recursive,
				OwnerOnly:  md.OwnerOnly,
				ReadOnly:   md.ReadOnly,
				FromSource: sourcePaths(md.FromSource),
				Severity:   md.Severity,
				RuleName:   name,
				Message:    md.Message,
			})
		}
		for _, mpat := range file.MatchPatterns {
			if mpat.Action != "Block" {
				continue
			}
			rules = append(rules, esRule{
				Operation: "file",
				MatchType: "glob",
				Value:     mpat.Pattern,
				OwnerOnly: mpat.OwnerOnly,
				ReadOnly:  mpat.ReadOnly,
				Severity:  mpat.Severity,
				RuleName:  name,
				Message:   mpat.Message,
			})
		}
	}

	return rules
}

func sourcePaths(src []tp.MatchSourceType) []string {
	out := make([]string, 0, len(src))
	for _, s := range src {
		if s.Path != "" {
			out = append(out, s.Path)
		}
	}
	return out
}

// serializeRuleset renders the TSV wire form:
//
//	RULESET\t<version>\t<count>\n
//	<op>\t<severity>\t<matchType>\t<value>\t<recursive>\t<ownerOnly>\t<readOnly>\t<fromSourceCSV>\t<ruleName>\t<message>\n   (x count)
//
// op is "process" or "file". Empty fields are kept (the helper's split preserves
// them); values are flattened to a single TSV cell by tsvField.
func serializeRuleset(version int, rules []esRule) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "RULESET\t%d\t%d\n", version, len(rules))
	for _, r := range rules {
		fmt.Fprintf(&b, "%s\t%d\t%s\t%s\t%t\t%t\t%t\t%s\t%s\t%s\n",
			r.Operation, r.Severity, r.MatchType, tsvField(r.Value),
			r.Recursive, r.OwnerOnly, r.ReadOnly,
			tsvField(strings.Join(r.FromSource, ",")), tsvField(r.RuleName), tsvField(r.Message))
	}
	return []byte(b.String())
}

// tsvField keeps a value on a single TSV cell. Paths and rule names never
// legitimately contain a tab or newline.
func tsvField(s string) string {
	return strings.NewReplacer("\t", " ", "\n", " ", "\r", " ").Replace(s)
}
