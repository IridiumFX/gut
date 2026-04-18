# gut knowledge transfer

Deep technical context for continuing development. Load alongside
[CLAUDE.md](./CLAUDE.md).

---

## 1. Architecture

### Directory layout

```
gut/
├── CLAUDE.md                     # session orientation
├── knowledge-transfer.md         # this file
├── roadmap.md                    # what's done + next
├── now.pasta                     # now build descriptor (authoritative)
├── CMakeLists.txt                # CMake fallback (IDE integration)
├── src/main/
│   ├── c/                        # 15 gut-proper .c files
│   │   ├── main.c                # ~9200 lines, CLI + dispatch + cmd_*
│   │   ├── repo.c                # init, open (with gitfile resolution), resolve_ref
│   │   ├── odb.c                 # object DB: loose read/write, pack load, algo-aware
│   │   ├── object.c              # blob/tree/commit/tag parse + serialize, tree_parse_algo
│   │   ├── oid.c                 # oid_to_hex_n / oid_from_hex_n (width-aware)
│   │   ├── sha1.c                # our SHA-1 impl (apennines has sha256)
│   │   ├── index.c               # .git/index v2 read/write, tree read
│   │   ├── pack.c                # pack_write_hinted, pack_index_create_algo, pack_read_object
│   │   ├── delta.c               # FNV-hash delta encoder with lazy + backward extension
│   │   ├── remote.c              # smart HTTP client (discover_refs / fetch_pack_algo / send_pack_algo)
│   │   ├── submodule.c           # .gitmodules parser + per-submodule clone
│   │   ├── config.c              # INI parser for .git/config and .gitmodules
│   │   ├── ignore.c              # .gitignore glob matcher
│   │   ├── leech.c               # P2P WebSocket client/server + ambient awareness
│   │   └── login.c               # OIDC device flow + credential store
│   └── h/gut/                    # public headers
└── lib/apennines/                # vendored apennines (32 .c files)
    ├── now.pasta                 # makes apennines a static-lib subcomponent
    ├── c/
    └── h/
```

Top-level `now.pasta` uses `sources.include` to pull apennines C
files directly into gut's compilation (no separate static archive
stage). The sub-`now.pasta` in `lib/apennines/` exists because rc1's
auto-scanner demands a descriptor in every `lib/*` subdir.

### Module dependency graph (simplified)

```
main.c (CLI) ──┬──> repo.c ─────┬──> odb.c ──> pack.c ──> delta.c
               │                │             └─> object.c ──> sha1.c / apennines/hash.c
               ├──> index.c ────┘
               ├──> remote.c    ──> apennines (http_client, https_client, tls, tcp, ws, buf, json, ...)
               ├──> submodule.c ──> remote.c + odb.c
               ├──> leech.c     ──> apennines (ws, http_client)
               ├──> login.c     ──> apennines (https_client, oauth2_client)
               └──> config.c / ignore.c (leaf helpers)
```

---

## 2. Code conventions (hard rules)

These are non-negotiable — every new file must follow them.

### 2.1 Calling convention

Every function in gut (and apennines) returns `unsigned long`:
- **0** = success
- **non-zero** = the `__LINE__` of the failure site

First parameter is the output pointer. Remaining parameters are inputs.

```c
/* Good */
unsigned long oid_from_hex_n(gut_oid *out, const char *hex, unsigned n);

/* The line-number hatch */
unsigned long foo(int *out, int x) {
    if (!out) return __LINE__;
    if (x < 0) return __LINE__;
    *out = x * 2;
    return 0;
}
```

When bubbling up, error messages preserve the line number so the
failing site can be found:

```c
if (rc) {
    fprintf(stderr, "error: foo failed (line %lu)\n", rc);
    return 1;
}
```

### 2.2 Types

Use apennines aliases, never raw C types for sized integers:

| Use | Instead of |
|---|---|
| `u8`, `u16`, `u32`, `u64` | `uint8_t`, `unsigned int`, etc. |
| `i8`, `i16`, `i32`, `i64` | `int8_t`, `int`, etc. |
| `f32`, `f64` | `float`, `double` |

Exceptions: `int argc, char **argv`, `size_t` for stdlib fread-style
calls, `FILE *`, `DIR *` — standard C interop.

### 2.3 Naming

`module_operation` style, snake_case:
- `pack_write`, `pack_index_create_algo`, `pack_idx_lookup`
- `tree_parse`, `tree_parse_algo`, `tree_serialize`
- `submodules_read`, `submodules_update_all`
- `oid_to_hex_n`, `oid_from_hex_n`, `oid_compare`

Algo-aware variants of hash-width-dependent functions get the `_algo`
suffix and take a `gut_hash_algo` parameter. The algo-less variant
wraps it with SHA-1:

```c
unsigned long pack_write(char *out, const char *dir,
                         gut_odb *odb, gut_oid *oids, u64 count) {
    return pack_write_hinted(out, dir, odb, oids, NULL, count);
}
```

### 2.4 Error-hatch discipline

Never silently swallow errors. Either:
1. Bubble up: `if (rc) return __LINE__;`
2. Print and return non-zero to main: `if (rc) { fprintf(stderr, ...); return 1; }`
3. Best-effort fallback: comment explicitly why a failure is OK.

---

## 3. SHA-1 / SHA-256 dual-width model

Shipped across four phases (all complete).

### Width widening
`gut_oid` is always 32 bytes wide in memory. For SHA-1, only the first
20 are significant; the tail is explicitly zeroed on load:

```c
typedef struct { u8 bytes[GUT_OID_MAX_RAW_SIZE]; } gut_oid;  /* 32 */
```

Width helpers:
```c
unsigned gut_oid_raw_size(gut_hash_algo a) { return a == GUT_HASH_SHA256 ? 32 : 20; }
unsigned gut_oid_hex_size(gut_hash_algo a) { return a == GUT_HASH_SHA256 ? 64 : 40; }
```

### Width-aware conversion
```c
unsigned long oid_to_hex_n(char *out, gut_oid *oid, unsigned n);
unsigned long oid_from_hex_n(gut_oid *out, const char *hex, unsigned n);
```

For a 40-char parse, the tail is zeroed; for 64-char, all 32 bytes are filled.

### Repo-level plumbing
`gut_repo.hash_algo` is read from `.git/config` `[extensions] objectformat`.
`repo_open` populates it and propagates to `odb.hash_algo`. Every
width-dependent operation reads repo->hash_algo:

- `odb_object_path` — builds `<prefix>/<rest>` using full hex length.
- `odb_resolve_prefix` — scans with correct width, supports short SHA.
- `index_read / index_write` — entry prelude size and trailer size vary.
- `tree_parse_algo` — OID field per entry is `oid_raw` bytes.
- `commit_parse` — auto-detects hex width (40 or 64) in tree/parent lines.
- `pack_write_hinted`, `pack_index_create_algo`, `pack_open_algo`,
  `pack_idx_lookup`, `pack_read_object` — all algo-aware.

### Wire protocol
- Server: `/info/refs` advertises `object-format=sha256` capability
  when repo is SHA-256; emit hex at repo's width. `srv_collect_refs`
  uses `hex_len` for file-name matching.
- Client: detects width from first-space position in first ref line,
  cross-checks via `strstr(caps, "object-format=sha256")`.

### Repo-config gotcha
SHA-256 repos require `repositoryformatversion = 1` in `.git/config`
because any `[extensions]` section requires v1. `cmd_init` and
`cmd_clone` rewrite the config when setting SHA-256.

---

## 4. Pack writer design

### 4.1 Sliding-window delta compression
`pack_write_hinted` takes optional parallel `paths[]` array. Three-strategy sort:

| Sort | When | Key |
|---|---|---|
| `(type, size desc)` | paths == NULL | Similar types cluster, big object first. |
| `(type, basename, size desc)` | paths != NULL | Versions of same file cluster; size-desc picks the biggest version as the base within a cluster. |

Window size `GUT_DELTA_WINDOW = 10`. Within the window, each object
attempts to delta-encode against every valid candidate of the same
type; if the smallest delta beats raw compressed size by > 30 bytes,
OFS_DELTA is emitted. Otherwise straight zlib.

### 4.2 Path collection (push only)
`walk_tree_objects(result, odb, tree_oid, prefix)` records each
blob's full path into `result->paths[i]`. Mode-040000 subtrees
recurse with an extended prefix; mode-160000 (submodules) are
skipped. `cmd_push` passes `objects.paths` through to
`pack_write_hinted`.

Measured on gut's own 28-commit history (349 objects):
**−9.86%** pack size (417,792 B vs 463,495 B) with path hints.

Recency-weighted alternative (newest-first from BFS insertion order)
was benchmarked and **not shipped** — it wins ~2% on non-monotonic
repos but loses ~2% on the far more common monotonic-growth case.
Code comment in `pack.c` documents the tradeoff.

### 4.3 Delta encoder
`delta.c` uses FNV-style 16-bit hash of 16-byte windows, chained
buckets (4 slots), with round-robin eviction.

- **Stride-indexed base** — stride=4 at 1 MiB bases, stride=16 at
  16 MiB, stride=1 below. Keeps indexing fast on large bases.
- **Lazy matching** — at each match, peek at pos+1 for a strictly
  longer match. `LAZY_CAP = 64` bypasses lookahead for very long
  matches.
- **Backward extension** — unbounded walk `base[bi-1] == target[pos-1]`
  recovers stride-gap prefixes of any length.

"Literal-region rescue" (re-scanning every literal byte for missed
matches) was prototyped and reverted: +15% encode time, 0% size
improvement on gut's history. The narrow scenario where rescue helps
(matches of length 16-18 at stride-unaligned positions) doesn't occur
in normal workloads.

### 4.4 Pack hashing
`pack_hasher` is a union of `sha1_ctx` and `sha256_ctx` with
`ph_init/update/final/digest` dispatchers. All pack-level hashing
(trailer, idx hash) goes through this for algo-parity.

---

## 5. Submodules

MVP: http/https only. SSH URLs are cleanly skipped with a message.

- `.gitmodules` parsed via the existing `config_read` (same INI).
  Entries combine `[submodule "<name>"]` path + url lines.
- Gitfile resolution lives in `repo.c:resolve_git_dir` — detects `.git`
  as a text file, reads `gitdir: <relpath>`, resolves relative to the
  gitfile's parent dir, uses that as `git_dir`.
- Tree mode 160000 (gitlink) entries skip blob materialization in
  `read_tree_recursive` (index.c) and the index doesn't track them.
- `submodules_update_all` walks parent HEAD's tree for each submodule
  path, finds the mode-160000 entry, pulls the recorded OID. Clones
  each submodule into `.git/modules/<name>/`, writes gitfile at
  `<submodule-path>/.git`, checks out the pinned commit.

Verified against VulpesIFF: `gut clone --recurse-submodules` pins
`dependencies/VulpesCore` at the same commit (`6a6508dc...`) that
`git clone --recursive` produces.

---

## 6. Server

### 6.1 Smart HTTP
- `/info/refs?service=git-upload-pack` / `?service=git-receive-pack`
- `/git-upload-pack` POST (wants → closure → packed response)
- `/git-receive-pack` POST (command list → pack → report-status)

Multi-repo via `--root <dir>`; single-repo via `--repo <path>`.
Path routing through `srv_split_path` finds the endpoint within a
multi-segment URL.

### 6.2 REST browse
- `GET /repos` — JSON array of repo names
- `GET /commits/<oid>` — commit JSON (tree, parents, author, committer, message)
- `GET /tree/<oid>` — tree entries array

All support short-SHA prefix resolution. JSON is hand-emitted via
`srv_json_escape_str` (apennines' `json.c` is a parser, not a writer).

### 6.3 TLS
`--cert <pem> --key <pem>` switches the listener to TLS 1.3.
PEM→DER decode handles PKCS#8 unwrap (most `openssl req` keys).
Cipher: `TLS_AES_128_GCM_SHA256`. Signature: `rsa_pss_rsae_sha256`.
Verified interop with openssl s_client, curl, real `git clone https://`.

### 6.4 Auth
`--auth-token <t>` accepts either:
- `Authorization: Bearer <t>`
- `Authorization: Basic <base64(x-oauth-basic:<t>)>`

Otherwise 401 + `WWW-Authenticate: Basic realm="gut"`.

---

## 7. P2P layer (unique to gut, beyond git)

See `leech.c`. Three building blocks:

1. **gut listen** — broker daemon. WebSocket server + outbound leech
   connections to discovered peers. `--background` / `--status` /
   `--stop` / PID file.
2. **gut leech** — ambient awareness. Subscribes to peer ref updates;
   auto-fetches into `refs/leech/<peer>/<branch>`.
3. **gut feeling** — predicts merge conflicts from leeched peer state
   before commit. diff3-based classification: CLEAN / MATCH / OVERLAP /
   CONFLICT. Inline conflict preview on CONFLICT rows.

Plus `gut ask / offer / sos` as ref-level coordination primitives,
`gut offer --patch` for targeted per-file patches with fetch-URL
fallback for large blobs, and full tie-break negotiation (lex-smaller
name wins, 60s staleness window).

---

## 8. Mailbox protocol (inter-team coordination)

**Location:** `~/.claude/mailbox/`

**Our files:**
- `from-gut.md` — we append outbound messages here (broadcast)
- `to-gut.md` — other teams append messages addressed to us here
- `to-<team>.md` / `from-<team>.md` — symmetric files for each peer

**Peer teams:**

| Team | Role | Mailbox |
|---|---|---|
| **apennines** | Runtime library (TLS, HTTP, crypto, buf, diff, net). Vendored at `lib/apennines/`. | `to-apennines.md` / `from-apennines.md` |
| **now** | Build system (1.0.0-rc1). Builds gut. | `to-now.md` / `from-now.md` |
| **cookbook** | Registry/artifact server. Less direct interaction. | `to-cookbook.md` / `from-cookbook.md` |
| **pasta** | Config format used by now.pasta descriptors. | (less active, same protocol) |

**Message format:**
```
## YYYY-MM-DD HH:MM UTC  | From: gut  | To: <team>

Subject: <short title>

<body>

— gut
```

**Rules:**
- Append-only — never rewrite history.
- One topic per message.
- Check when the user tells you to, or at session start.
- Use `tail -NN /c/Users/Iridium/.claude/mailbox/to-gut.md` — don't
  read the whole file (can grow large).
- For shared source files: drop in `~/.claude/mailbox/{team}-for-{team}/`.

**Examples of what goes through the mailbox:**
- Bug reports up the stack (gut → apennines): http_response_parse
  short-body bug, TLS PKCS#8 unwrap bug.
- Migration help (gut ↔ now): `sources.include` semantics, cold-build
  benchmark data.
- Broadcast milestones (to `from-gut.md`): major feature completions.

**Full spec:** `~/.claude/mailbox/interconnection-protocol.md`.

---

## 9. Build recipes

### Incremental build
```bash
export PATH="/c/Program Files/JetBrains/CLion 2025.3.3/bin/mingw/bin:$PATH"
taskkill //F //IM gut.exe 2>/dev/null  # release file lock
C:/Users/Iridium/Projects/now/build/static/bin/now.exe build
```

### Clean build
```bash
rm -rf target lib/apennines/target
now build
```

### Clear ccache (for benchmarking true cold)
```bash
rm -rf ~/.now/cache
```

### CMake fallback
```bash
cd build
cmake -G Ninja ..
ninja
# Output at build/gut.exe
```

### Benchmark methodology
See `mailbox/to-now.md` entries around 2026-04-18 for the
apples-to-apples harness. Ninja cold is highly sensitive to OS file
cache state (12-18s range); average 2-3 runs.

---

## 10. Testing recipes

No formal test harness yet — integration tests are scripted. Some
battle-tested patterns:

### Full round-trip with real git
```bash
# Seed a gut repo
mkdir /tmp/seed && cd /tmp/seed && gut init .
echo hello > a.txt && gut add a.txt && gut commit -m c0

# Serve it, clone with real git
(cd /tmp && gut server --port 7789 --repo /tmp/seed &)
git clone http://127.0.0.1:7789/ /tmp/clone
cd /tmp/clone && git log --oneline
```

### Pack-size A/B
```bash
# Use GUT_NO_PATH_HINTS=1 and GUT_SORT_MODE (if you restore the env
# toggles) to compare delta strategies. Currently the toggles are
# removed — re-add them temporarily for any new benchmark.
```

### SHA-256 interop
```bash
gut init --object-format sha256 /tmp/s256
# ... commits ...
# Real git sees this (git 2.39+) if config has repositoryformatversion=1
```

### VulpesIFF submodule smoke
```bash
rm -rf /tmp/vif && cd /tmp
gut clone --recurse-submodules https://github.com/IridiumFX/VulpesIFF.git vif
# Expect: VulpesCore cloned, IFF-2025 skipped (SSH URL)
cat /tmp/vif/.git/modules/dependencies/VulpesCore/HEAD
# Should be: 6a6508dca2ec62fca14bd733dfba2d62df93066a
```

---

## 11. Known limitations & Tier-4 horizon

Complete list in `roadmap.md` under "Tier 4: Full drop-in git
replacement". Summary:

- **SSH transport** — blocks `git@host:...` URLs. Needs apennines
  SSH client stack first.
- **Interactive rebase** — we have `squash` + `amend` as primitives.
- **Cherry-pick** — small module, reuses diff3.
- **Reflog** — needs ref-update hook in `repo_update_ref`.
- **Worktree add** — gitfile resolution already done (from submodules).
- **Partial clone `--filter`** — orthogonal to existing `--depth`.
- **Credential helpers** — standard `credential.helper` protocol
  (interop with system keychains).

---

## 12. Gotchas for future sessions

1. **Windows file lock on gut.exe**: if a `gut.exe` instance is
   running (from a previous test), the linker can't overwrite it.
   Always `taskkill //F //IM gut.exe` before rebuilding.

2. **gcc PATH**: the MinGW gcc isn't on PATH by default. Tests
   silently fail to link with "failed to spawn compiler" or
   permission errors. Always export PATH before building from a new
   shell.

3. **now binaries come in pairs**:
   `C:/Users/Iridium/Projects/now/build/static/bin/now.exe` — 1-file
   drop-in. `build/default/bin/now.exe` — shared-lib version. Both
   work; static is cleaner for benchmarks.

4. **ccache masks cold builds**: `~/.now/cache` persists across
   runs. Clear it for true-cold benchmarks; keep it for realistic
   dev-iteration measurements.

5. **Memory lines in MEMORY.md cap at 200**: keep entries short. Full
   detail belongs in this file or roadmap.md.

6. **Server stderr bleeds into bash $(...) capture**: when starting
   gut server in a background subshell for tests, redirect its
   stderr/stdout to /dev/null or a log file or it contaminates the
   captured return value.

7. **SHA-256 config requires `repositoryformatversion = 1`**: git
   refuses to open the repo otherwise. Both `cmd_init` and
   `cmd_clone` rewrite the config when switching to sha256.

8. **`oid_set_add_with_path` vs `oid_set_add`**: the former records
   a path for basename-clustering in `pack_write_hinted`; the latter
   leaves it NULL. Only blobs get paths; commits and trees don't
   need them (basename "" clusters them together).

9. **Submodule URLs**: if `.gitmodules` has an `ssh://` or
   `git@host:path` URL, skip it with the "unsupported scheme" message
   rather than failing the whole clone.

10. **Apennines calling convention across module boundaries**: when
    modifying code in apennines (via `lib/apennines/`), return
    line-number codes and bubble them up the same way. Apennines
    functions uniformly return `unsigned long`.
