# KubeArmor macOS Enforcer — Apple Endpoint Security Architecture

> Status: **experimental**. Phase 0 (observability + audit classification) ships in
> the Go daemon with no native code. Phase 1 (process‑exec **block prevention**) adds
> the `kubearmor-es-helper` native client — it needs `com.apple.developer.endpoint-security.client`,
> so on a stock Mac it requires an Apple‑granted entitlement, or a SIP+AMFI‑disabled
> box for local dev. See §6–§7.

KubeArmor enforces policy on Linux through Linux Security Modules (BPF‑LSM, AppArmor,
SELinux). macOS has no LSM; the equivalent kernel primitive is Apple's
**Endpoint Security (ES)** framework — kernel‑mediated **AUTH** events that a userspace
client must `ALLOW` or `DENY` within a deadline.

On macOS KubeArmor runs as a **host enforcer only** (`-enableKubeArmorHostPolicy`,
non‑Kubernetes). There are no cgroups or PID namespaces, so container/endpoint
selectors do not apply — every event is host scope.

---

## 1. High‑level block diagram

```
 ┌─────────────────────────────────────────────────────────────────────────────────┐
 │                    KubeArmor daemon  (Go, single cross-platform binary,         │
 │                     unentitled, unchanged from Linux)                           │
 │                                                                                 │
 │   KubeArmorHostPolicy ──► feeder.UpdateHostSecurityPolicies                     │
 │        (CRD / file)              │                                              │
 │                                  ▼                                              │
 │                       feeder policyMatcher   ──────────────┐                    │
 │                                  │  compiled rules         │ compiled ruleset   │
 │                                  │                         ▼  (SET_RULESET)     │
 │   ┌──────────────┐   PushLog     │            ┌────────────────────────────┐    │
 │   │  gRPC feeds  │◄──────────────┤            │  RuntimeEnforcer           │    │
 │   │  Alerts/Logs │               │            │  EnforcerType =            │    │
 │   └──────────────┘               │            │  "AppleEndpointSecurity"   │    │
 │        ▲     ▲                   │            └─────────────┬──────────────┘    │
 │        │     │                   │                          │ AF_UNIX           │
 │        │     │ visibility +      │                          │ /var/run/         │
 │        │     │ AUDIT violations  │                          │ kubearmor/es.sock │
 │        │     │                   │                          │                   │
 │        │  ┌──┴───────────────┐   │            ┌─────────────▼──────────────────┐│
 │        │  │ eslogger reader  │   │            │ BLOCKED frame (complete,       ││
 │        │  │ monitor/esmonitor│   │            │ self-contained) ──────────────┐││
 │        │  └──────┬───────────┘   │            └────────────────────────────┐  │││
 │        │         │ JSON NOTIFY   │                                         │  │││
 │  block │         │ (op proceeds) │                                         │  │││
 │  alerts│         ▼               │                                         │  │││
 └────────┼─────────┼───────────────┼─────────────────────────────────────────┼──┼┼┘
          │  ┌──────┴─────────┐     │            ┌────────────────────────────┴──┴┐│
          │  │ /usr/bin/      │     │            │  kubearmor-es-helper           ││
          │  │ eslogger       │     │            │  (C, signed + notarized,      ││
          │  │ (Apple binary, │     │            │   ES entitlement) — Phase 1+  ││
          │  │  NOTIFY only)  │     │            │                               ││
          │  └──────┬─────────┘     │            │  • es_new_client              ││
          │         │               │            │  • subscribe AUTH_* ONLY      ││
          │         ▼               │            │  • allow/deny from ruleset    ││
          │   ┌───────────────┐     │            │    within kernel deadline     ││
          └───┤   XNU kernel  ├─────┼────────────┤  • inverted path muting       ││
              │ EndpointSecurity    │            │  • on DENY: build full alert  ││
              │   subsystem    │◄───┘  AUTH_*    │    from AUTH msg + proc_pidpath││
              └───────────────┘   (exec / open   │  • NO NOTIFY, NO JSON,        ││
                                   / unlink…)    │    NO long-lived proc tree    ││
                                                 └───────────────────────────────┘│
                                                  runs as: standalone entitled    │
                                                  binary (dev) or SystemExtension │
                                                  in a .app (GA)                  │
```

**Reading the diagram**

* The **Go daemon** is unchanged from Linux — no entitlement, no notarization for ES,
  one cross‑platform binary. It compiles the policy and owns the gRPC feeds.
* **`eslogger`** (Apple's own, already‑notarized, TCC‑blessed CLI) supplies every
  event for an operation that **proceeds** — general visibility and `Audit`‑mode
  policy violations.
* The **`kubearmor-es-helper`** (Phase 1+) is the only component that needs the ES
  entitlement and notarization. It subscribes to **AUTH events only**, answers
  allow/deny from a pushed ruleset, and on a denial relays a **complete** block event.
* A blocked operation never generates a NOTIFY event, so `eslogger` cannot see it —
  but the helper already holds every needed attribute in the AUTH message it just
  handled, so it reports the block itself. The two event sources are therefore
  **disjoint**: no correlation, no de‑duplication.

---

## 2. Endpoint Security vs `eslogger`

| | ES client (our helper) | `eslogger` (Apple binary) |
|---|---|---|
| Events | NOTIFY **and** AUTH | NOTIFY only |
| Can block? | **Yes** (`es_respond_auth_result` / `es_respond_flags_result`) | No |
| Entitlement | `com.apple.developer.endpoint-security.client` (Apple‑granted) | none needed by the caller |
| Packaging | signed + **notarized**; standalone entitled binary (dev) or SystemExtension in a `.app` (GA) | ships with macOS, already notarized |
| User consent | approve the System Extension | grant **Full Disk Access** (TCC) |
| Privilege | root | root |
| Min macOS | 12 (13 for inverted path muting, used for `AUTH_OPEN` performance) | 13 |
| Output schema | stable C API | JSON, documented as "for debugging" — parsed leniently |

Enforcement **requires** our own entitled ES client. `eslogger` alone provides
visibility and post‑hoc audit alerts but cannot prevent anything.

---

## 3. Responsibilities (disjoint, no cross‑source join)

### 3.1 `kubearmor-es-helper` — enforcement **and** its own block alerts

Deliberately minimal, because every line must be Apple‑notarized (and, as a System
Extension, user‑approved). "Minimal" means **AUTH‑only, no NOTIFY subscription, no
JSON, no long‑lived process tree** — *not* "emit a stub the daemon has to enrich".

1. `es_new_client`, subscribe to AUTH events only:
   `AUTH_EXEC`, `AUTH_OPEN`, `AUTH_CREATE`, `AUTH_UNLINK`, `AUTH_RENAME`,
   `AUTH_TRUNCATE`, `AUTH_CLONE`, `AUTH_LINK`, `AUTH_SETMODE` / `AUTH_SETOWNER` /
   `AUTH_SETFLAGS`, `AUTH_MOUNT`.
2. Apply the pushed ruleset. `es_mute_process` for KubeArmor's own pids and a built‑in
   critical‑infrastructure allowlist. `es_mute_path` **inverted** so `AUTH_OPEN` and
   the file‑mutation events fire only for paths named in the ruleset.
3. Per message: match against the ruleset, respond `ALLOW` / `DENY` within the kernel
   deadline. Cache stable `ALLOW` decisions.
4. **On `DENY` only:** assemble a complete `BLOCKED` frame and write it to the socket.
   Every field comes from the AUTH message that was just handled:

   | `tp.Log` field | ES source |
   |---|---|
   | `PID` / `PPID` / `UID` (euid) | `audit_token`, `es_process_t.ppid` |
   | `ProcessName` (acting exe) | `es_message_t.process.executable.path` |
   | `ParentProcessName` | `proc_pidpath(ppid)` (libproc — no ES, no NOTIFY, no entitlement) |
   | `Resource` (target) | `es_event_exec_t.target.executable.path` / `es_event_open_t.file.path` / … |
   | `OID` (target owner) | `es_file_t.stat.st_uid` (drives `ownerOnly`) |
   | `Cwd` | `es_event_exec_t.cwd.path` (exec) / `proc_pidinfo` (file ops) |
   | `TTY` | `es_message_t.process.tty.path` (drives `pts`) |
   | `Data` | open flags (`es_event_open_t.fflag` → `flags=O_RDONLY|…`), signing id / team id |
   | `Source` | acting exe (+ argv for exec) |
   | `PolicyName` / `Severity` / `Tags` / `Message` | the matched rule (the helper holds the compiled ruleset) |

5. Nothing else — no `ALLOW` / `AUDIT` frames. Operations that proceed are `eslogger`'s
   job.

### 3.2 `eslogger` — visibility and `Audit`‑mode violations

The Go daemon spawns `eslogger --format json <events>` as a supervised child, reads
line‑delimited JSON, normalises each record to a `tp.Log`, and calls
`feeder.PushLog`. The existing `feeder.UpdateMatchedPolicy` then classifies it:

* matches an `action: Audit` rule or a default `audit` posture with an allow‑list →
  `MatchedHostPolicy` **alert** (`Action=Audit`), emitted regardless of the visibility
  flags;
* otherwise → `HostLog` **visibility** record, emitted only if the matching
  `-hostVisibility` flag (`process` / `file` / `network`) is set.

`eslogger` needs root + **Full Disk Access**. Without it the daemon still runs:
enforcement and block alerts (helper‑sourced) are unaffected; only visibility and
audit‑mode alerts are lost.

#### Subscribed events

Always: `exec exit fork create unlink rename truncate setmode setowner`, plus the
session/login/auth set (`openssh_login openssh_logout login_login login_logout
lw_session_login lw_session_logout lw_session_lock lw_session_unlock
screensharing_attach screensharing_detach su sudo authentication` — see §4.3;
human‑rate events, unconditional, no visibility flag needed).
`open` is added **only when file visibility is enabled** (`-hostVisibility=…,file`) —
`open` fires on nearly every file access and `eslogger` has no path filter, so it is
a firehose. Without `open` there is no file‑*read* visibility and `readOnly` file
rules cannot match; the volume‑free version of this is the Phase 1 ES client with
inverted path muting.

#### `tp.Log` field mapping (`eslogger` JSON → KubeArmor log)

| `tp.Log` field | exec (`event.exec`) | file event |
|---|---|---|
| `Operation` | `Process` | `File` |
| `Resource` | `target.executable.path` (+ `argv[1:]`) | affected path |
| `ProcessName` | `target.executable.path` | `process.executable.path` |
| `ParentProcessName` | `process.executable.path` | exe of `ppid` (from the exec cache) |
| `Source` | `process.executable.path` (parent, matches Linux) | acting process full command line |
| `Cwd` | `event.exec.cwd.path` | acting process cwd (from the exec cache) |
| `TTY` | `target.tty.path` → `process.tty.path` | `process.tty.path` |
| `Data` | `syscall=execve` | `syscall=<op>` + `flags=…` / `mode=…` / `userid=… group=…` |
| `OID` | `target.executable.stat.st_uid` | affected inode `stat.st_uid` (drives `ownerOnly`) |
| `ExecEvent.ExecutableName` / `ExecID` | `basename(exe)` / `pid.pidversion` | same |
| `ProcessHash` / `ParentHash` / `HashAlgo` | `cdhash` of target / of `ppid` / `cdhash` | `cdhash` of acting / of `ppid` / `cdhash` |
| `Result` | `Passed` (NOTIFY = it happened) | `Passed` |

`HostName` / `ClusterName` / `NodeID` / `UserName` are filled by the feeder. On the
standard `CGO_ENABLED=0` build, `UserName` resolution falls back to `id -nu <uid>`
(`feeder/username_darwin.go`) because `os/user.LookupId` cannot see Directory Services
users without cgo.

Known difference from Linux: the extra `Operation=Syscall, Action=Audit` duplicate
log that Linux emits for audited syscalls is not produced on the ES path.

### 3.3 The Go daemon

* Compiles `KubeArmorHostPolicy` process/file rules into the ruleset pushed to the
  helper (reuses `feeder`'s `newMatchPolicy` shape).
* `RuntimeEnforcer` gains `EnforcerType = "AppleEndpointSecurity"`; the enforcer
  selection on darwin skips the `/sys/kernel/security/lsm` probe.
* All events — helper `BLOCKED` frames and `eslogger` records — converge on the single
  `feeder.PushLog` sink already used by every non‑eBPF producer
  (`networkPolicyEnforcer`, presets, the BPF‑LSM enforcer).

---

## 4. Rule → ES event mapping

| KubeArmor rule | ES enforcement |
|---|---|
| **Process** `Path` / `Directory(+Recursive)` / `Pattern`, `fromSource`, `ownerOnly`, `action` | `AUTH_EXEC` — match `es_event_exec_t.target.executable.path`; `fromSource` → initiating `process.executable.path`; `ownerOnly` → euid vs target `st_uid`; `Block` → `ES_AUTH_RESULT_DENY` |
| **File** `Path` / `Directory(+Recursive)` / `Pattern`, `fromSource`, `ownerOnly`, `readOnly`, `action` | `AUTH_OPEN` (respond with an fflags mask: `readOnly` masks off write bits, `Block` = `0`), `AUTH_CREATE` / `AUTH_UNLINK` / `AUTH_RENAME` / `AUTH_TRUNCATE` / `AUTH_SETMODE` / … (`DENY`) |
| **Default posture** `block` \| `audit` | in‑scope `block` is honoured **only within the union of policy‑named path subtrees** (see safety rail); outside them the effective posture is `audit` |
| **Network** rules | out of scope — handled by `networkPolicyEnforcer` (ES network events are NOTIFY‑only) |
| **`Syscalls`** `matchSyscalls` (repurposed for session/login/auth — see §4.3) | `eslogger` NOTIFY only — always `Audit` (`SyscallsType` has no `action` field) |

### 4.1 `AUTH_OPEN` performance

`AUTH_OPEN` fires on nearly every file access. It is made tractable by:

1. **inverted target‑path muting** — subscribe only for the concrete paths and
   directory subtrees in the active ruleset;
2. **decision caching** — `es_respond_auth_result(..., cache=true)` for stable
   `ALLOW`s;
3. **process muting** — KubeArmor's own pids plus the critical‑infrastructure
   allowlist;
4. a strict per‑message CPU budget; on a ruleset miss, `ALLOW` immediately.

### 4.2 Default‑deny safety rail

A host‑wide `block` default posture on macOS can render the system unusable (deny
`dyld`, `launchd`, a shell) and is infeasible to evaluate within the AUTH deadline
system‑wide. Therefore a `block` default posture is enforced **only inside the union
of policy‑named path subtrees**. A genuinely host‑wide default‑deny is opt‑in via
`--es-allow-hostwide-deny` together with a built‑in immutable allowlist
(`/usr/lib/dyld`, `/sbin/launchd`, `/bin/**`, `/usr/lib/system/**`, `/System/**`
executables, and the helper + daemon themselves).

### 4.3 Session / login / auth audit

Apple ES also has NOTIFY events for SSH login/logout, console login/logout,
loginwindow session login/logout/lock/unlock, screen sharing attach/detach, `su`,
and `sudo`. **None of them has an `AUTH_*` counterpart** (verified against
`EndpointSecurity/ESTypes.h` and `eslogger --list-events`) — auth has already
happened by the time ES sees it, so this category is audit‑only, structurally.

That lines up with KubeArmor's existing `spec.syscalls` category: its rule type
(`SyscallsType`/`SyscallMatchType`) has **no `action` field at all** — a syscall
rule is always `Audit`. `eslogger`'s own event names are used as the "syscall"
identifier:

```yaml
apiVersion: security.kubearmor.com/v1
kind: KubeArmorHostPolicy
metadata:
  name: audit-login-and-privesc
spec:
  nodeSelector:
    matchLabels:
      kubearmor.io/hostname: '*'
  syscalls:
    matchSyscalls:
    - syscall: ["openssh_login", "openssh_logout", "login_login", "login_logout"]
      severity: 5
      message: "user session activity"
    - syscall: ["su", "sudo"]
      severity: 8
      message: "privilege escalation"
    - syscall: ["lw_session_lock", "lw_session_unlock", "screensharing_attach", "screensharing_detach"]
      severity: 3
      message: "screen / remote session activity"
```

`matchSyscalls[].fromSource[].path` filters by the acting username (e.g.
`fromSource: [{path: "root"}]` to only alert on root logins) — `dir`/`recursive`
don't apply to a username and are simply unused for this category. No new policy
schema, no `.proto`/CRD change: these events are wired entirely in
`monitor/esmonitor_darwin.go`, which builds `Data = "syscall=SYS_<NAME> ..."` —
the exact shape `feeder/policyMatcher.go`'s existing `Syscall`‑operation matcher
already parses for Linux syscall auditing.

### 4.4 ⚠️ Path gotcha: write `/private/...`, never `/etc`, `/tmp`, or `/var`

On macOS, `/etc`, `/tmp`, and `/var` are **symlinks** to `/private/etc`,
`/private/tmp`, `/private/var` (`ls -la /` confirms it: `/etc -> private/etc`).
Endpoint Security always reports the **resolved, canonical path** — a write to
`/etc/pam.d/sudo` arrives as `/private/etc/pam.d/sudo`. Every `Path`/`Directory`
match (`matchPaths`, `matchDirectories`, in both `spec.process` and `spec.file`,
for `Audit` and `Block` alike) is a **literal path-prefix comparison**, so a rule
written as `/etc/pam.d/` or `/tmp/` will **silently never match** — no error, no
log, just no alert. Always write the `/private/...` form:

| write this | not this |
|---|---|
| `/private/etc/pam.d/` | `/etc/pam.d/` |
| `/private/tmp/` | `/tmp/` |
| `/private/var/log/` | `/var/log/` |

If a rule "isn't firing" and the path is under one of these three roots, this is
the first thing to check.

---

## 5. Degradation ladder

`karmor probe` reports the active state:

| helper | `eslogger` | state | behaviour |
|---|---|---|---|
| connected | up | **Enforced** | block rules prevent; audit rules + visibility observed |
| connected | down (no FDA) | **Enforced (no visibility)** | block rules prevent and still produce full alerts; no audit alerts / visibility |
| unavailable (no approval / entitlement / macOS &lt; 12) | up | **Audited** | violations recorded, nothing prevented |
| unavailable | down | **Disabled** | — |

---

## 6. Phasing

* **Phase 0** — no native code, no entitlement. `eslogger` reader → `feeder.PushLog`;
  visibility + `Audit`‑mode alerts; `Block` rules *recorded, not prevented*.
* **Phase 1** — `kubearmor-es-helper` (C, AUTH‑only) + `AF_UNIX` transport +
  Go ruleset compiler + `AUTH_EXEC` **block prevention** + self‑contained `BLOCKED`
  frames. Scope: process `exec`.
* **Phase 2 (current)** — file block prevention: `AUTH_OPEN` (fflags mask —
  `Block` = deny, `readOnly` = strip the write bit) + `AUTH_CREATE` / `UNLINK` /
  `RENAME` / `TRUNCATE` / `SETMODE` / `SETOWNER` / `SETFLAGS` (`DENY` on a matching
  `file` `Block`/`readOnly` rule). `ownerOnly` = euid vs target `st_uid`.
  Performance: **inverted target‑path muting** (macOS 13+) scopes AUTH events to the
  ruleset's paths. `Audit`/`Allow` rules are still compiled to nothing for the
  helper — they work via the Phase 0 path.
* **Phase 3** — host‑wide default‑deny posture + `--es-allow-hostwide-deny`,
  `LINK`/`CLONE`/xattr events, decision‑cache tuning, SystemExtension packaging,
  `OSSystemExtensionRequest` activation UX, notarization, the Apple‑granted
  entitlement. Observability stays on `eslogger`.

---

## 7. Running it

### Phase 0 — visibility + audit (any signed / notarized build)

```
sudo ./kubearmor -k8s=false -enableKubeArmorHostPolicy=true \
  -lsm=AppleEndpointSecurity -hostVisibility=process,file -logPath=/tmp/kubearmor.log
```

Grant the terminal (or the `kubearmor` binary) **Full Disk Access** so the child
`eslogger` can start. Apply a `KubeArmorHostPolicy`; observe `karmor logs` /
`karmor alerts`.

### Phase 1 — block enforcement

**Build the helper.** `com.apple.developer.endpoint-security.client` is an
Apple‑managed entitlement — two paths:

| | dev now | release |
|---|---|---|
| Entitlement | ad‑hoc `codesign -s -` (honoured only on a SIP+AMFI‑disabled box) | Apple‑granted, org account; System Extension request form |
| Machine | dedicated test Mac / UTM VM with `csrutil disable` **and** `nvram boot-args="amfi_get_out_of_my_way=0x1"` | any stock Mac |
| Command | `make build-es-helper` | `make build-es-helper SIGN_ID="Developer ID Application: <Org> (<TEAMID>)"` then `xcrun notarytool submit` |

```
# on the SIP+AMFI-disabled dev box:
make -C KubeArmor build-es-helper
sudo ./kubearmor -k8s=false -enableKubeArmorHostPolicy=true \
  -lsm=AppleEndpointSecurity -hostVisibility=process,file \
  -esHelperPath=./kubearmor-es-helper -logPath=/tmp/kubearmor.log
```

The daemon spawns and supervises the helper. On connect it logs
`helper connected (v1) - enforcing`; `karmor probe` shows
`ActiveLSM=AppleEndpointSecurity`. Apply a `KubeArmorHostPolicy` with
`action: Block` on a process rule (e.g. `dir: /private/tmp/`). A matching exec now
**fails** (`Operation not permitted`) and produces one alert:
`Enforcer=AppleEndpointSecurity, Type=MatchedHostPolicy, Action=Block,
Result="Permission denied"`.

If the helper cannot start (missing entitlement, not root, no FDA for `es_new_client`
on some macOS builds) it sends `UNAVAILABLE` and the daemon stays observe‑only —
`Block` rules are recorded via `eslogger` but not prevented. `dyld` / `launchd` /
`/bin/*` / `/usr/bin/*` / `/usr/lib/*` / `/System/Library/*` are never mediated
(boot‑safety mute), so a broad `Block` rule cannot wedge the system.
