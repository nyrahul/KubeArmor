// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor
//
// kubearmor-es-helper — the native Apple Endpoint Security client for KubeArmor's
// macOS host enforcer. It answers ES AUTH events for process exec and file
// mutation, applying a compiled Block ruleset received from the KubeArmor daemon
// over an AF_UNIX socket (TSV frames). On a denial it sends back one JSON
// "BLOCKED" frame built entirely from the AUTH message plus proc_pidpath(ppid);
// it keeps no process tree and never subscribes to NOTIFY events.
//
// Enforced events:
//   AUTH_EXEC                                   — process rules
//   AUTH_OPEN                                   — file rules: write-mode opens are
//                                                 denied outright (Block) or have
//                                                 the write bit stripped (readOnly)
//   AUTH_CREATE / UNLINK / RENAME / TRUNCATE /  — file rules: every one of these is
//   SETMODE / SETOWNER / SETFLAGS                 a modification, so a matching
//                                                 Block *or* readOnly rule denies
//
// Performance: target-path muting is inverted (macOS 13+) so AUTH events fire
// only for paths named by the ruleset; an empty ruleset delivers nothing. A rule
// with no usable literal prefix (process execName, a pattern whose first path
// component is a wildcard) forces full delivery and logs a warning.
//
// Build: see Makefile (clang -lEndpointSecurity -lbsm, then codesign with
//        es.entitlements). Must run as root on a host that honours the ES
//        entitlement (Apple-granted, or a SIP+AMFI-disabled dev box).

#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <dispatch/dispatch.h>
#include <errno.h>
#include <fnmatch.h>
#include <libproc.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

// The ES open event fflag is the kernel FFLAGS form (see <sys/fcntl.h>), not raw
// O_* values: a read-only open is FREAD with FWRITE clear.
#ifndef FREAD
#define FREAD 0x0001
#endif
#ifndef FWRITE
#define FWRITE 0x0002
#endif

// ---------------------------------------------------------------- ruleset ------

typedef struct {
    char  operation[8];   // process | file
    char  match_type[12]; // path | dir | glob | execname
    char *value;
    bool  recursive;
    bool  owner_only;
    bool  read_only;
    char *from_source;    // comma-separated, may be ""
    int   severity;
    char *rule_name;
    char *message;
} rule_t;

typedef struct {
    rule_t *rules;
    int     n;
    int     version;
} ruleset_t;

static ruleset_t     *g_rs = NULL;
static pthread_rwlock_t g_rs_lock = PTHREAD_RWLOCK_INITIALIZER;
static int            g_sock = -1;
static es_client_t   *g_client = NULL;
static volatile atomic_bool g_running = true;
static bool          g_debug = false; // KUBEARMOR_ES_DEBUG=1

static char *xstrndup(const char *s, size_t n) {
    char *p = malloc(n + 1);
    if (!p) return NULL;
    memcpy(p, s, n);
    p[n] = '\0';
    return p;
}

static char *dup_tok(es_string_token_t t) {
    return xstrndup(t.data ? t.data : "", t.data ? t.length : 0);
}

static void free_ruleset(ruleset_t *rs) {
    if (!rs) return;
    for (int i = 0; i < rs->n; i++) {
        free(rs->rules[i].value);
        free(rs->rules[i].from_source);
        free(rs->rules[i].rule_name);
        free(rs->rules[i].message);
    }
    free(rs->rules);
    free(rs);
}

// split_tsv splits line in place on '\t' preserving empty fields (strtok_r would
// collapse them and shift every later column). Returns the field count.
static int split_tsv(char *line, char *fields[], int max) {
    int nf = 0;
    char *cur = line;
    while (nf < max) {
        fields[nf++] = cur;
        char *t = strchr(cur, '\t');
        if (!t) break;
        *t = '\0';
        cur = t + 1;
    }
    return nf;
}

// parse_ruleset consumes "RULESET\t<ver>\t<count>\n<rows...>". Each row is:
//   <op>\t<severity>\t<matchType>\t<value>\t<recursive>\t<ownerOnly>\t<readOnly>\t<fromSourceCSV>\t<ruleName>\t<message>
static ruleset_t *parse_ruleset(char *buf) {
    char *nl = strchr(buf, '\n');
    if (!nl) return NULL;
    *nl = '\0';
    if (strncmp(buf, "RULESET\t", 8) != 0) return NULL;

    int ver = 0, count = 0;
    sscanf(buf + 8, "%d\t%d", &ver, &count);
    if (count < 0) count = 0;

    ruleset_t *rs = calloc(1, sizeof(*rs));
    rs->version = ver;
    rs->rules = calloc(count > 0 ? count : 1, sizeof(rule_t));

    char *p = nl + 1;
    while (rs->n < count && *p) {
        char *eol = strchr(p, '\n');
        if (eol) *eol = '\0';

        char *f[10] = {0};
        int nf = split_tsv(p, f, 10);
        if (nf >= 9) {
            rule_t *r = &rs->rules[rs->n++];
            strncpy(r->operation, f[0], sizeof(r->operation) - 1);
            r->severity    = atoi(f[1]);
            strncpy(r->match_type, f[2], sizeof(r->match_type) - 1);
            r->value       = strdup(f[3]);
            r->recursive   = strcmp(f[4], "true") == 0;
            r->owner_only  = strcmp(f[5], "true") == 0;
            r->read_only   = strcmp(f[6], "true") == 0;
            r->from_source = strdup(f[7]);
            r->rule_name   = strdup(f[8]);
            r->message     = strdup(nf > 9 ? f[9] : "");
        }

        if (!eol) break;
        p = eol + 1;
    }
    return rs;
}

// -------------------------------------------------------- target-path muting ---

// rule_prefix writes the longest literal path prefix of a rule's target into out.
// Returns false when the rule has no usable prefix (execName, or a pattern whose
// first path component is a wildcard); the caller then falls back to unmuted.
static bool rule_prefix(const rule_t *r, char *out, size_t cap, bool *is_literal) {
    *is_literal = false;
    if (strcmp(r->match_type, "path") == 0) {
        strlcpy(out, r->value, cap);
        *is_literal = true;
        return out[0] == '/';
    }
    if (strcmp(r->match_type, "dir") == 0) {
        strlcpy(out, r->value, cap);
        return out[0] == '/';
    }
    if (strcmp(r->match_type, "glob") == 0) {
        size_t i = 0;
        for (; r->value[i] && i + 1 < cap; i++) {
            char ch = r->value[i];
            if (ch == '*' || ch == '?' || ch == '[') break;
            out[i] = ch;
        }
        out[i] = '\0';
        char *sl = strrchr(out, '/'); // keep up to the last complete component
        if (!sl) return false;
        sl[1] = '\0';
        return out[0] == '/' && strlen(out) > 1;
    }
    return false; // execname
}

// apply_target_mutes rebuilds the inverted target-path allow set from rs. With
// muting inverted, es_mute_path() *selects* a path: only selected paths deliver
// AUTH events. An empty set delivers nothing (allow-all — correct for no rules).
static void apply_target_mutes(ruleset_t *rs) {
    if (!g_client) return;
    es_unmute_all_target_paths(g_client);

    bool unmuted = false;
    for (int i = 0; i < rs->n; i++) {
        char pfx[1200];
        bool literal = false;
        if (!rule_prefix(&rs->rules[i], pfx, sizeof(pfx), &literal)) {
            unmuted = true;
            continue;
        }
        es_mute_path(g_client, pfx,
                     literal ? ES_MUTE_PATH_TYPE_TARGET_LITERAL
                             : ES_MUTE_PATH_TYPE_TARGET_PREFIX);
        if (g_debug)
            fprintf(stderr, "  select %s (%s)\n", pfx,
                    literal ? "target-literal" : "target-prefix");
    }
    if (unmuted) {
        es_mute_path(g_client, "/", ES_MUTE_PATH_TYPE_TARGET_PREFIX);
        fprintf(stderr, "WARNING: a rule has no literal path prefix; AUTH events "
                        "run unmuted (performance impact under file load)\n");
    }
}

static void swap_ruleset(ruleset_t *nrs) {
    pthread_rwlock_wrlock(&g_rs_lock);
    ruleset_t *old = g_rs;
    g_rs = nrs;
    pthread_rwlock_unlock(&g_rs_lock);
    free_ruleset(old);

    apply_target_mutes(nrs);
    if (g_client) es_clear_cache(g_client);

    fprintf(stderr, "ruleset v%d: %d block rule(s)\n", nrs->version, nrs->n);
    for (int i = 0; i < nrs->n; i++) {
        rule_t *r = &nrs->rules[i];
        fprintf(stderr, "  [%d] %s %s=%s recursive=%d ownerOnly=%d readOnly=%d "
                        "fromSource=[%s] rule=%s\n",
                i, r->operation, r->match_type, r->value, r->recursive,
                r->owner_only, r->read_only, r->from_source, r->rule_name);
    }
}

// --------------------------------------------------------------- matching -----

static bool tok_eq(es_string_token_t t, const char *s) {
    return t.data && strlen(s) == t.length && memcmp(t.data, s, t.length) == 0;
}

static int slash_count(const char *s, size_t len) {
    int n = 0;
    for (size_t i = 0; i < len; i++) if (s[i] == '/') n++;
    return n;
}

// last_slash returns a pointer to the final '/' in s[0..len), or NULL.
static const char *last_slash(const char *s, size_t len) {
    for (size_t i = len; i > 0; i--)
        if (s[i - 1] == '/') return s + (i - 1);
    return NULL;
}

// from_source_match returns true when csv is empty, or the instigator path is one
// of the comma-separated entries.
static bool from_source_match(const char *csv, es_string_token_t inst) {
    if (!csv || !*csv) return true;
    char *dup = strdup(csv), *ls = NULL;
    bool hit = false;
    for (char *e = strtok_r(dup, ",", &ls); e; e = strtok_r(NULL, ",", &ls)) {
        if (tok_eq(inst, e)) { hit = true; break; }
    }
    free(dup);
    return hit;
}

// is_protected_target: access to these targets is always allowed, regardless of
// policy, so a broad rule can't wedge boot / login / the dylib loader. Matched on
// the *target* path (the binary being exec'd, or the file being touched), not the
// instigating process.
static bool is_protected_target(const char *p) {
    static const char *pfx[] = {
        "/System/", "/usr/lib/", "/usr/libexec/", "/bin/", "/sbin/",
        "/usr/bin/", "/usr/sbin/", "/Library/Apple/", NULL,
    };
    if (strcmp(p, "/usr/lib/dyld") == 0) return true;
    for (int i = 0; pfx[i]; i++)
        if (strncmp(p, pfx[i], strlen(pfx[i])) == 0) return true;
    return false;
}

// match_path_rule reproduces the path-matching subset of feeder/policyMatcher.go
// (exact path / dir prefix+depth / execName suffix / glob) plus fromSource and
// ownerOnly. It does not check r->operation — the caller pre-filters.
static bool match_path_rule(const rule_t *r, const char *target, size_t tlen,
                            es_string_token_t inst, uid_t euid, uid_t target_uid) {
    bool m = false;
    if (strcmp(r->match_type, "path") == 0) {
        m = strlen(r->value) == tlen && memcmp(r->value, target, tlen) == 0;
    } else if (strcmp(r->match_type, "execname") == 0) {
        const char *base = last_slash(target, tlen);
        base = base ? base + 1 : target;
        size_t blen = tlen - (size_t)(base - target);
        m = strlen(r->value) == blen && memcmp(r->value, base, blen) == 0;
    } else if (strcmp(r->match_type, "glob") == 0) {
        char *t = xstrndup(target, tlen);
        m = t && fnmatch(r->value, t, 0) == 0;
        free(t);
    } else if (strcmp(r->match_type, "dir") == 0) {
        size_t plen = strlen(r->value);
        if (plen <= tlen && memcmp(r->value, target, plen) == 0) {
            const char *slash = last_slash(target, tlen);
            size_t dlen = slash ? (size_t)(slash - target) + 1 : tlen;
            int want = slash_count(r->value, plen);
            int got  = slash_count(target, dlen);
            m = r->recursive ? (got >= want) : (got == want);
        }
    }
    if (!m) return false;
    if (!from_source_match(r->from_source, inst)) return false;
    // ownerOnly Block applies to non-owners; the owner is allowed through.
    if (r->owner_only && euid == target_uid) return false;
    return true;
}

// find_hit returns the first rule of the given operation that matches target.
// want_write says whether the operation modifies the target: a readOnly rule
// matches only modifications, a full Block rule matches any access.
static const rule_t *find_hit(ruleset_t *rs, const char *op, const char *target,
                              size_t tlen, es_string_token_t inst, uid_t euid,
                              uid_t tuid, bool want_write) {
    if (!rs) return NULL;
    for (int i = 0; i < rs->n; i++) {
        const rule_t *r = &rs->rules[i];
        if (strcmp(r->operation, op) != 0) continue;
        if (r->read_only && !want_write) continue;
        if (match_path_rule(r, target, tlen, inst, euid, tuid)) return r;
    }
    return NULL;
}

// ---------------------------------------------------------------- socket ------

static void json_escape(const char *s, char *out, size_t cap) {
    size_t o = 0;
    for (size_t i = 0; s && s[i] && o + 6 < cap; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '"' || c == '\\') { out[o++] = '\\'; out[o++] = c; }
        else if (c == '\n') { out[o++] = '\\'; out[o++] = 'n'; }
        else if (c == '\t') { out[o++] = '\\'; out[o++] = 't'; }
        else if (c < 0x20) { o += snprintf(out + o, cap - o, "\\u%04x", c); }
        else out[o++] = c;
    }
    out[o] = '\0';
}

// send_frame writes a 4-byte big-endian length prefix + payload. best-effort.
static void send_frame(const char *payload, bool nonblock) {
    if (g_sock < 0) return;
    uint32_t n = (uint32_t)strlen(payload);
    unsigned char hdr[4] = { n >> 24, n >> 16, n >> 8, n };
    int flags = nonblock ? MSG_DONTWAIT : 0;
    if (send(g_sock, hdr, 4, flags) != 4) return;
    send(g_sock, payload, n, flags);
}

// emit_blocked assembles the self-contained BLOCKED frame. op is "Process" or
// "File"; target is the resource path (exec'd binary / touched file); data is the
// "syscall=… [flags=…]" hint. For exec it also carries argv and cwd.
static void emit_blocked(const es_message_t *msg, const rule_t *r,
                         const char *op, const char *target, const char *data) {
    const es_process_t *p = msg->process;
    bool  is_exec = msg->event_type == ES_EVENT_TYPE_AUTH_EXEC;
    pid_t pid  = audit_token_to_pid(p->audit_token);
    uid_t euid = audit_token_to_euid(p->audit_token);
    pid_t ppid = p->ppid;

    // exe = the process this event is about; parentExe = who launched it.
    char exe[1200] = "", parent[1200] = "";
    if (is_exec) {
        es_string_token_t t = msg->event.exec.target->executable->path;
        snprintf(exe, sizeof(exe), "%.*s", (int)t.length, t.data ? t.data : "");
        snprintf(parent, sizeof(parent), "%.*s",
                 (int)p->executable->path.length, p->executable->path.data);
    } else {
        snprintf(exe, sizeof(exe), "%.*s",
                 (int)p->executable->path.length, p->executable->path.data);
        proc_pidpath(ppid, parent, sizeof(parent));
    }

    char cwd[1200] = "";
    if (is_exec && msg->version >= 3 && msg->event.exec.cwd)
        snprintf(cwd, sizeof(cwd), "%.*s",
                 (int)msg->event.exec.cwd->path.length, msg->event.exec.cwd->path.data);

    char tty[256] = "";
    if (msg->version >= 2 && p->tty)
        snprintf(tty, sizeof(tty), "%.*s",
                 (int)p->tty->path.length, p->tty->path.data);

    char args[4096] = "[";
    if (is_exec) {
        uint32_t ac = es_exec_arg_count(&msg->event.exec);
        for (uint32_t i = 0; i < ac && strlen(args) < sizeof(args) - 300; i++) {
            es_string_token_t a = es_exec_arg(&msg->event.exec, i);
            char raw[512], esc[1024];
            snprintf(raw, sizeof(raw), "%.*s", (int)a.length, a.data ? a.data : "");
            json_escape(raw, esc, sizeof(esc));
            strlcat(args, i ? ",\"" : "\"", sizeof(args));
            strlcat(args, esc, sizeof(args));
            strlcat(args, "\"", sizeof(args));
        }
    }
    strlcat(args, "]", sizeof(args));

    char e_exe[1400], e_parent[1400], e_target[1400], e_cwd[1400], e_tty[300],
         e_data[256], e_rule[512], e_msg[1024];
    json_escape(exe, e_exe, sizeof(e_exe));
    json_escape(parent, e_parent, sizeof(e_parent));
    json_escape(target, e_target, sizeof(e_target));
    json_escape(cwd, e_cwd, sizeof(e_cwd));
    json_escape(tty, e_tty, sizeof(e_tty));
    json_escape(data, e_data, sizeof(e_data));
    json_escape(r->rule_name, e_rule, sizeof(e_rule));
    json_escape(r->message, e_msg, sizeof(e_msg));

    char buf[16384];
    snprintf(buf, sizeof(buf),
        "{\"kind\":\"BLOCKED\",\"op\":\"%s\",\"pid\":%d,\"ppid\":%d,\"euid\":%d,"
        "\"exe\":\"%s\",\"parentExe\":\"%s\",\"target\":\"%s\",\"cwd\":\"%s\","
        "\"tty\":\"%s\",\"args\":%s,\"data\":\"%s\",\"rule\":\"%s\",\"severity\":%d,"
        "\"message\":\"%s\",\"ts\":%lld}",
        op, pid, ppid, euid, e_exe, e_parent, e_target, e_cwd, e_tty, args,
        e_data, e_rule, r->severity, e_msg, (long long)time(NULL));
    send_frame(buf, /*nonblock=*/true);
}

// -------------------------------------------------------------- ES handlers ---

static void handle_exec(es_client_t *c, const es_message_t *msg) {
    const es_process_t *tgt = msg->event.exec.target;
    es_string_token_t tp = tgt->executable->path;
    es_string_token_t inst = msg->process->executable->path;
    uid_t euid = audit_token_to_euid(msg->process->audit_token);
    uid_t tuid = tgt->executable->stat.st_uid;

    char *target = dup_tok(tp);
    if (is_protected_target(target)) {
        es_respond_auth_result(c, msg, ES_AUTH_RESULT_ALLOW, true);
        free(target);
        return;
    }

    es_auth_result_t res = ES_AUTH_RESULT_ALLOW;
    bool cache = true;
    char hitname[128] = "";

    pthread_rwlock_rdlock(&g_rs_lock);
    ruleset_t *rs = g_rs;
    const rule_t *hit = find_hit(rs, "process", target, tp.length, inst, euid, tuid, true);
    int nrules = rs ? rs->n : 0;
    if (hit) {
        res = ES_AUTH_RESULT_DENY;
        cache = false;
        strncpy(hitname, hit->rule_name, sizeof(hitname) - 1);
        emit_blocked(msg, hit, "Process", target, "syscall=execve");
    }
    pthread_rwlock_unlock(&g_rs_lock);

    es_respond_auth_result(c, msg, res, cache);

    if (res == ES_AUTH_RESULT_DENY)
        fprintf(stderr, "DENY exec %s (rule %s)\n", target, hitname);
    else if (g_debug)
        fprintf(stderr, "allow exec %s (%d rule(s), no match)\n", target, nrules);

    free(target);
}

static void handle_open(es_client_t *c, const es_message_t *msg) {
    const es_file_t *f = msg->event.open.file;
    es_string_token_t fp = f->path;
    es_string_token_t inst = msg->process->executable->path;
    uid_t euid = audit_token_to_euid(msg->process->audit_token);
    uid_t tuid = f->stat.st_uid;
    bool write = (msg->event.open.fflag & FWRITE) != 0;

    char *target = dup_tok(fp);
    if (is_protected_target(target)) {
        es_respond_flags_result(c, msg, 0xffffffff, true);
        free(target);
        return;
    }

    char hitname[128] = "";
    bool strip_write = false, deny_all = false;

    pthread_rwlock_rdlock(&g_rs_lock);
    const rule_t *hit = find_hit(g_rs, "file", target, fp.length, inst, euid, tuid, write);
    if (hit) {
        strncpy(hitname, hit->rule_name, sizeof(hitname) - 1);
        if (hit->read_only) {
            strip_write = true; // allow the read, drop the write bit
        } else {
            deny_all = true;    // full Block: no access at all
        }
        char data[64];
        snprintf(data, sizeof(data), "syscall=open flags=%s",
                 write ? "O_WRONLY" : "O_RDONLY");
        emit_blocked(msg, hit, "File", target, data);
    }
    pthread_rwlock_unlock(&g_rs_lock);

    if (deny_all) {
        es_respond_flags_result(c, msg, 0, false);
        fprintf(stderr, "DENY open %s (rule %s)\n", target, hitname);
    } else if (strip_write) {
        es_respond_flags_result(c, msg, (uint32_t)(msg->event.open.fflag & ~FWRITE), false);
        fprintf(stderr, "DENY write-open %s (rule %s)\n", target, hitname);
    } else {
        es_respond_flags_result(c, msg, 0xffffffff, true);
    }

    free(target);
}

// handle_mutation covers unlink/rename/truncate/setmode/setowner/setflags/create.
// target is heap-allocated by the caller; this frees it. Every such event is a
// modification, so a matching Block or readOnly file rule denies it.
static void handle_mutation(es_client_t *c, const es_message_t *msg,
                            const char *syscall_name, char *target, uid_t tuid) {
    es_string_token_t inst = msg->process->executable->path;
    uid_t euid = audit_token_to_euid(msg->process->audit_token);

    if (!target || !*target || is_protected_target(target)) {
        es_respond_auth_result(c, msg, ES_AUTH_RESULT_ALLOW, true);
        free(target);
        return;
    }

    es_auth_result_t res = ES_AUTH_RESULT_ALLOW;
    char hitname[128] = "";

    pthread_rwlock_rdlock(&g_rs_lock);
    const rule_t *hit = find_hit(g_rs, "file", target, strlen(target), inst, euid, tuid, true);
    if (hit) {
        res = ES_AUTH_RESULT_DENY;
        strncpy(hitname, hit->rule_name, sizeof(hitname) - 1);
        char data[64];
        snprintf(data, sizeof(data), "syscall=%s", syscall_name);
        emit_blocked(msg, hit, "File", target, data);
    }
    pthread_rwlock_unlock(&g_rs_lock);

    es_respond_auth_result(c, msg, res, /*cache=*/false);

    if (res == ES_AUTH_RESULT_DENY)
        fprintf(stderr, "DENY %s %s (rule %s)\n", syscall_name, target, hitname);
    else if (g_debug)
        fprintf(stderr, "allow %s %s (no match)\n", syscall_name, target);

    free(target);
}

static void handle_create(es_client_t *c, const es_message_t *msg) {
    const es_event_create_t *ev = &msg->event.create;
    if (ev->destination_type == ES_DESTINATION_TYPE_EXISTING_FILE) {
        handle_mutation(c, msg, "create", dup_tok(ev->destination.existing_file->path),
                        ev->destination.existing_file->stat.st_uid);
        return;
    }
    const es_file_t *dir = ev->destination.new_path.dir;
    es_string_token_t nm = ev->destination.new_path.filename;
    size_t dl = dir->path.length;
    char *full = malloc(dl + 1 + nm.length + 1);
    if (!full) {
        es_respond_auth_result(c, msg, ES_AUTH_RESULT_ALLOW, true);
        return;
    }
    memcpy(full, dir->path.data, dl);
    full[dl] = '/';
    memcpy(full + dl + 1, nm.data ? nm.data : "", nm.length);
    full[dl + 1 + nm.length] = '\0';
    handle_mutation(c, msg, "create", full, dir->stat.st_uid);
}

static void on_message(es_client_t *c, const es_message_t *msg) {
    switch (msg->event_type) {
    case ES_EVENT_TYPE_AUTH_EXEC:
        handle_exec(c, msg);
        break;
    case ES_EVENT_TYPE_AUTH_OPEN:
        handle_open(c, msg);
        break;
    case ES_EVENT_TYPE_AUTH_CREATE:
        handle_create(c, msg);
        break;
    case ES_EVENT_TYPE_AUTH_UNLINK:
        handle_mutation(c, msg, "unlink", dup_tok(msg->event.unlink.target->path),
                        msg->event.unlink.target->stat.st_uid);
        break;
    case ES_EVENT_TYPE_AUTH_RENAME:
        handle_mutation(c, msg, "rename", dup_tok(msg->event.rename.source->path),
                        msg->event.rename.source->stat.st_uid);
        break;
    case ES_EVENT_TYPE_AUTH_TRUNCATE:
        handle_mutation(c, msg, "truncate", dup_tok(msg->event.truncate.target->path),
                        msg->event.truncate.target->stat.st_uid);
        break;
    case ES_EVENT_TYPE_AUTH_SETMODE:
        handle_mutation(c, msg, "chmod", dup_tok(msg->event.setmode.target->path),
                        msg->event.setmode.target->stat.st_uid);
        break;
    case ES_EVENT_TYPE_AUTH_SETOWNER:
        handle_mutation(c, msg, "chown", dup_tok(msg->event.setowner.target->path),
                        msg->event.setowner.target->stat.st_uid);
        break;
    case ES_EVENT_TYPE_AUTH_SETFLAGS:
        handle_mutation(c, msg, "chflags", dup_tok(msg->event.setflags.target->path),
                        msg->event.setflags.target->stat.st_uid);
        break;
    default:
        es_respond_auth_result(c, msg, ES_AUTH_RESULT_ALLOW, true);
    }
}

// ------------------------------------------------------------ socket reader ---

static bool read_full(int fd, void *buf, size_t n) {
    unsigned char *p = buf;
    while (n) {
        ssize_t r = recv(fd, p, n, 0);
        if (r <= 0) return false;
        p += r;
        n -= (size_t)r;
    }
    return true;
}

static void *reader_thread(void *arg) {
    (void)arg;
    fprintf(stderr, "reader thread up, waiting for frames on fd %d\n", g_sock);
    for (;;) {
        unsigned char hdr[4];
        if (!read_full(g_sock, hdr, 4)) break;
        uint32_t len = (hdr[0] << 24) | (hdr[1] << 16) | (hdr[2] << 8) | hdr[3];
        if (len == 0 || len > (16u << 20)) break;
        char *buf = malloc(len + 1);
        if (!buf || !read_full(g_sock, buf, len)) { free(buf); break; }
        buf[len] = '\0';

        if (g_debug)
            fprintf(stderr, "frame: %u bytes, starts \"%.20s\"\n", len, buf);

        if (strncmp(buf, "RULESET\t", 8) == 0) {
            ruleset_t *nrs = parse_ruleset(buf);
            if (nrs) swap_ruleset(nrs);
            else fprintf(stderr, "parse_ruleset returned NULL for a RULESET frame\n");
        } else if (strncmp(buf, "PING", 4) == 0) {
            send_frame("{\"kind\":\"PONG\"}", false);
        }
        free(buf);
    }
    // daemon gone -> exit; the KubeArmor supervisor will respawn us
    atomic_store(&g_running, false);
    if (g_client) es_delete_client(g_client);
    exit(0);
    return NULL;
}

// ---------------------------------------------------------------- main --------

static int connect_socket(const char *path) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_un sa = {0};
    sa.sun_family = AF_UNIX;
    strlcpy(sa.sun_path, path, sizeof(sa.sun_path));
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void on_sig(int s) {
    (void)s;
    atomic_store(&g_running, false);
    if (g_client) es_delete_client(g_client);
    exit(0);
}

int main(int argc, char **argv) {
    setvbuf(stderr, NULL, _IONBF, 0); // daemon captures stderr via a pipe
    g_debug = getenv("KUBEARMOR_ES_DEBUG") != NULL;
    fprintf(stderr, "kubearmor-es-helper starting (pid %d, uid %d, debug %d)\n",
            getpid(), geteuid(), g_debug);

    const char *sock_path = NULL;
    for (int i = 1; i < argc - 1; i++)
        if (strcmp(argv[i], "-socket") == 0) sock_path = argv[i + 1];
    if (!sock_path) {
        fprintf(stderr, "usage: kubearmor-es-helper -socket <path>\n");
        return 2;
    }

    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, on_sig);
    signal(SIGINT, on_sig);

    g_sock = connect_socket(sock_path);
    if (g_sock < 0) {
        fprintf(stderr, "cannot connect %s: %s\n", sock_path, strerror(errno));
        return 1;
    }
    fprintf(stderr, "connected to %s (fd %d)\n", sock_path, g_sock);

    es_new_client_result_t nr = es_new_client(&g_client, ^(es_client_t *c, const es_message_t *msg) {
        on_message(c, msg);
    });
    if (nr != ES_NEW_CLIENT_RESULT_SUCCESS) {
        const char *why =
            nr == ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED  ? "ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED (Full Disk Access / TCC or entitlement)" :
            nr == ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED ? "ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED (must run as root)" :
            nr == ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED   ? "ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED (com.apple.developer.endpoint-security.client missing)" :
                                                            "es_new_client failed";
        char frame[512];
        char esc[400];
        json_escape(why, esc, sizeof(esc));
        snprintf(frame, sizeof(frame), "{\"kind\":\"UNAVAILABLE\",\"reason\":\"%s\"}", esc);
        send_frame(frame, false);
        fprintf(stderr, "%s\n", why);
        return 1;
    }

    // Boot-safety is enforced per-event via is_protected_target() on the *target*
    // path. We do NOT es_mute_path() an instigator prefix (that would silence
    // every exec the user's shell performs). Target-path muting is inverted so
    // AUTH events fire only for the ruleset's paths; the set starts empty (nothing
    // delivered) and apply_target_mutes() fills it on each RULESET frame.
    es_unmute_all_target_paths(g_client);
    if (es_invert_muting(g_client, ES_MUTE_INVERSION_TYPE_TARGET_PATH) != ES_RETURN_SUCCESS)
        fprintf(stderr, "WARNING: es_invert_muting(TARGET_PATH) failed; "
                        "AUTH events run unmuted\n");

    es_event_type_t events[] = {
        ES_EVENT_TYPE_AUTH_EXEC,
        ES_EVENT_TYPE_AUTH_OPEN,
        ES_EVENT_TYPE_AUTH_CREATE,
        ES_EVENT_TYPE_AUTH_UNLINK,
        ES_EVENT_TYPE_AUTH_RENAME,
        ES_EVENT_TYPE_AUTH_TRUNCATE,
        ES_EVENT_TYPE_AUTH_SETMODE,
        ES_EVENT_TYPE_AUTH_SETOWNER,
        ES_EVENT_TYPE_AUTH_SETFLAGS,
    };
    if (es_subscribe(g_client, events, sizeof(events) / sizeof(events[0])) != ES_RETURN_SUCCESS) {
        fprintf(stderr, "es_subscribe failed\n");
        return 1;
    }
    fprintf(stderr, "ES client ready, subscribed AUTH_EXEC + file events\n");

    send_frame("{\"kind\":\"HELLO\",\"version\":1}", false);

    pthread_t rt;
    if (pthread_create(&rt, NULL, reader_thread, NULL) != 0)
        fprintf(stderr, "pthread_create(reader_thread) failed: %s\n", strerror(errno));

    dispatch_main(); // ES delivers on its own queue; this parks the main thread
    return 0;
}
