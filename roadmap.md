# gut roadmap

## Completed

### Core git compat
- [x] Object model: blob, tree, commit, tag
- [x] SHA-1 hashing (own implementation)
- [x] Loose object store (zlib read/write)
- [x] Packfile reader (.idx v2, OFS_DELTA, REF_DELTA)
- [x] **Packfile indexer** (`pack_index_create`) — writes .idx v2 for a
      received pack, bit-identical output to `git index-pack`
- [x] **Packfile writer** with delta compression (OFS_DELTA via sliding
      10-object same-type window; FNV-hash chained buckets, chain=4;
      git-parity compression ratios on source-code-like inputs)
- [x] **Large-offset table** (>2 GiB packs) in writer and indexer
- [x] Index v2 binary format (read/write)
- [x] Repository init/open with parent walk
- [x] Ref management (branches, tags, HEAD)
- [x] Atomic ref updates (.lock + rename)
- [x] Atomic index writes
- [x] Config reading (.git/config INI parser)
- [x] .gitignore with glob matching
- [x] Diff (patience algorithm, unified output)
- [x] Three-way merge (diff3 with conflict markers)
- [x] Short SHA prefix resolution
- [x] Full HTTPS client stack vendored (TLS 1.3, HTTP, crypto, PKI)

### Tier 3: Network operations
- [x] **gut clone** — smart HTTP ref discovery + pack download
- [x] **gut fetch** — incremental pack negotiation
- [x] **gut push** — pack writer + send via git-receive-pack
- [x] **gut login** — OIDC device flow + credential store
- [x] **gut remote** — add / remove / list / set-url for .git/config
- [x] **gut config** — get / set / --list via dot-path keys
- [x] **gut mv** — rename tracked file + index atomically
- [x] **gut ls-files** — one line per tracked path (for pipelines)

### P2P ambient coordination (beyond git)
- [x] **gut listen** — broker daemon (WS server + outbound leech connections)
      with `--background` / `--status` / `--stop` / PID file
- [x] **gut leech** — ambient awareness of peer ref updates
- [x] Auto-fetch on peer events into `refs/leech/<peer>/<branch>`
- [x] Bidirectional WebSocket (masked client→server, unmasked server→client)
- [x] **gut ask / gut offer / gut sos** — ref-level peer coordination primitives
- [x] **gut feeling** — predicts merge conflicts from leeched peer state
      before commit; classifies CLEAN / MATCH / OVERLAP / CONFLICT using
      diff3; inline conflict preview on CONFLICT rows
- [x] `gut add` post-hook warns on CONFLICT (silenceable with `GUT_NO_FEELING=1`)
- [x] `gut status` peer-activity section
- [x] `--since <duration>` filter on feeling and status
- [x] **gut offer --patch** — targeted per-file patch proposal; receiver
      persists under `.git/offers/<id>.json`, `gut offers apply|reject`

### Commands (30+)
init, add, unstage, rm, branch, branches, tag, tags, checkout, merge,
diff, commit, log, status, last, amend, undo, restore, reset,
hash-object, cat-file, clone, fetch, push, login, listen, leech, send,
leechers, ask, offer, offers, sos, feeling, repack, pack-objects,
index-pack

## In Progress

_(nothing active)_

## Tier 4: Full drop-in git replacement

These are the items that stand between gut and being a drop-in
replacement for `git` itself in any developer's daily workflow. The
common gap is that each of these requires its own small subsystem,
not just a command glued on top of existing primitives.

- [ ] **SSH transport** — `git@host:path` URLs. Biggest gap: most
      real-world clone URLs (github, gitlab) are SSH. Needs an SSH
      client stack in apennines (key exchange, userauth with public
      keys / agents, channel multiplexing, `git-upload-pack` /
      `git-receive-pack` command streams). Once apennines has it,
      `remote_discover_refs` + `remote_fetch_pack_algo` +
      `remote_send_pack_algo` get SSH siblings (or a transport
      abstraction layer).

- [ ] **Interactive rebase** — `gut rebase -i <upstream>`. We have
      `gut squash N` and `gut amend` as partial building blocks.
      Needs: a "todo script" (pick/reword/edit/squash/fixup/drop per
      commit), an editor-launcher, and the replay loop that walks
      commits in order, stopping on conflict and letting the user
      `--continue`/`--abort`. Non-interactive `gut rebase <upstream>`
      (just replay) is a useful intermediate milestone.

- [ ] **Cherry-pick** — `gut cherry-pick <commit>`. Replay one
      commit's diff onto HEAD. Reuses three-way-merge for conflict
      handling (we already have diff3). Small module.

- [ ] **Reflog** — `gut reflog` + implicit `.git/logs/HEAD` +
      `.git/logs/refs/heads/<name>` append on every ref update. Most
      invasive in `repo_update_ref` (needs old→new→timestamp→reason
      line format). Once the log file is written, `gut reflog` is
      just a file reader.

- [ ] **Worktree add** — `gut worktree add <path> <branch>`. Parent
      repo keeps the `.git/` dir; new worktrees at arbitrary paths
      get a gitfile (`.git` as text file pointing back). We already
      added gitfile support for submodules, so `repo_open` handles
      the indirection. Missing: the `.git/worktrees/<id>/` metadata
      dir and the list/remove/prune subcommands.

- [ ] **Partial clone / `--filter`** — `gut clone --filter=blob:none`
      / `--filter=tree:0`. We have `--depth` (shallow); partial
      clone is the orthogonal axis (don't fetch blobs or trees until
      needed). Needs: promisor-remote config, `GetObject` over smart
      HTTP for lazy resolution, `pack_index.v3`-style marking of
      missing objects.

- [ ] **Credential helpers** — the standard
      `credential.helper` protocol (`helper get/store/erase` via
      stdin/stdout). Currently `gut login` uses OIDC device flow to
      write to its own credential store; what's missing is cooperating
      with the system keychain helpers (`manager-core` on Windows,
      `osxkeychain` on Mac, `libsecret` on Linux) so users who already
      have git-credentials cached don't re-authenticate.

## Planned

### Delta encoder polish
- [x] **Lazy matching** — 1-byte lookahead at each match, commits the
      later one if longer. `LAZY_CAP=64` bounds the cost.
- [x] **Block-stride indexing** — stride=4 at 1 MiB bases, stride=16 at
      16 MiB, stride=1 below. Keeps indexing fast on large inputs.
- [x] **Pre-sort before `pack_write`** — preload + sort by
      (type asc, size desc) so the delta window sees good candidates.

### Delta encoder future
- [x] **Path-hint sort** — `pack_write_hinted` takes an optional
      parallel `paths` array; pre-sort uses (type asc, basename asc,
      size desc) when paths are supplied, so versions of the same file
      cluster for the sliding delta window. `oid_set` extended with a
      parallel `paths[]` field; push tree walk collects full blob
      paths. **Measured on gut's own 28-commit history (349 objects):
      −9.86%** (417,792 B vs 463,495 B). `pack_write` is a thin
      wrapper that passes NULL paths for back-compat (repack, server,
      clone-time pack builds unchanged).
- [x] **Recency-weighted sort — tested, size-desc retained as default.**
      Implemented discovery-order (orig_idx asc, newest-from-BFS first)
      as an alternative within-basename tiebreaker. Benchmarked on two
      shapes:
        • gut's own history (monotonic growth): size-desc wins by ~2%.
        • non-monotonic synthetic repo:         recency wins by ~2%.
      Net wash; since real C projects dominate the monotonic case,
      kept size-desc shipping. Code comment in pack.c documents the
      tradeoff for future revisits.
- [x] **Better backward-extension — investigated, current implementation
      is already sufficient.** Existing single-loop backward extension
      (`while base[bi-1] == target[pos-1]`) is unbounded and recovers
      stride-gap prefixes of any length, so matches missed by the
      stride-indexed forward scan are picked up. Prototyped a
      "literal-region rescue" that re-ran `find_best_match` at every
      byte of each pending literal region before flushing: +15% encode
      time on gut's history, 0% pack-size improvement. Reverted with
      a comment in `delta.c` documenting the finding for future revisit
      if a large-stride workload ever exposes a gap.

### Quality of life
- [x] `gut log --oneline` — short SHA + subject line
- [x] `gut log --graph` — single-column asterisk gutter
- [x] `gut log -n <count>` — limit output
- [x] `gut wip [<note>]` — commit with "WIP:" prefix + timestamp or note
- [x] `gut diff --stat` — summary with path | N +++---
- [x] `gut squash N [-m <msg>]` — collapse last N commits; refuses merges
- [x] `gut revert-file <commit> <path>` — restore single file from any commit
- [x] `gut stash` / `gut stash pop` / `gut stash list` — snapshot on refs/stashes/<ts>
- [x] `gut blame <path>` — per-line attribution via content-equality walk
- [x] `gut show [<commit>]` — commit header + diff vs first parent
- [x] `gut help` / `--help` / `-h` — grouped command list (40+ cmds)
- [x] Typo suggestion on unknown command (common-prefix heuristic)
- [x] Better error messages across individual commands (diffuse polish)
      — upgraded the top user-facing messages with actionable
      next-step hints:
        • `"not a gut repository"` now suggests `gut init` (42 sites,
          bulk replaced).
        • `"no remote configured"` in fetch/push now shows the exact
          `gut remote add origin <url>` command.
        • `"send failed"` in peer-protocol sends (ask/offer/sos) now
          asks whether a broker is listening and suggests
          `gut listen --background` on the peer.
        • `"bad default revision 'HEAD'"` → `"HEAD points to an
          unborn branch — run 'gut commit' first"`.
        • `"cannot resolve refs/heads/main"` on push points at the
          empty-repo case.
        • `"object not found"` in cat-file names the OID.
        • `"write failed"` names the path that couldn't be written.
      Line-number error hatches preserved.

### gut server
Self-hosted git-compatible server built on apennines tcp + http inline.
- [x] `gut server --port N --repo <path>` — clone-only MVP; real `git
      clone http://host:N/` succeeds with files + history
- [x] `/info/refs?service=git-upload-pack` + `/git-upload-pack` (wants →
      closure → packed response with sideband)
- [x] `/git-receive-pack` — real `git push` works; refs validated with
      fast-forward check; report-status pkt-lines back to client
- [x] Multi-repo: `--root <dir>` serves `/<repo-path>/info/refs` etc.;
      per-request open; `..` rejected
- [x] Auth: `--auth-token <t>` accepts `Authorization: Bearer <t>` or Basic `x-oauth-basic:<t>`; 401 + WWW-Authenticate otherwise
- [x] REST browse API — `GET /repos` (array of repo names served),
      `GET /commits/<oid>` (commit JSON with tree, parents, author,
      committer, message), `GET /tree/<oid>` (array of
      `{mode, type, name, oid}` entries). Multi-repo routing via
      `/<repo>/commits/<oid>`, `/<repo>/tree/<oid>`. Short-SHA prefix
      resolution. SHA-1 and SHA-256 both verified — OIDs in JSON match
      the repo's algo. Hand-rolled JSON emitter (apennines' json.c is
      a parser) with proper escaping for control chars and quotes.
- [x] TLS: `--cert <pem> --key <pem>`, PEM→DER decode with PKCS#8
      unwrap, srv_io wrapper, TLS 1.3 handshake on accept.
      Verified interop: openssl s_client, curl, `git clone https://`
      all complete cleanly. TLS_AES_128_GCM_SHA256 + rsa_pss_rsae_sha256.

### P2P layer 2+
- [x] `gut feeling --offer-to <url> --as <name>` — when CONFLICT detected,
      auto-send patch-offer to the listener (explicit opt-in flag; never
      folded into `gut add` so no surprise network activity)
- [x] Fetch-URL fallback in `offer --patch`: oversized blobs go out with
      empty `content_b64` + `fetch_url`, receiver pulls via /pack endpoint
      and verifies target_oid matches before persisting
- [x] Offer-ack: sender waits for `{op: "offer-accepted"}` or
      `{op: "offer-rejected", reason}` — synchronous outcome visibility
- [x] Full tie-break negotiation: sender persists `.git/offers-sent/`,
      listener scans for (path match + mtime < 60s) collisions, lex-smaller
      `as` name wins, loser accepts and drops own record. Verified in
      concurrent-fire test: alice's offer ACCEPTED, bob's REJECTED with
      tie-break reason, deterministic regardless of ordering.

### Future
- [x] SHA-256 object format (all 4 phases complete; git-interop verified):
      - [x] **Phase 1**: gut_oid widened to 32 bytes, `gut_hash_algo`
            enum, `obj_hash_sha256`/`obj_hash_algo`, width-aware
            `oid_to_hex_n` / `oid_from_hex_n`. SHA-1 paths unchanged.
            `gut hash-object --object-format=sha256 <file>` verified
            against openssl byte-for-byte.
      - [x] **Phase 2 scaffold**: `gut_repo.hash_algo` field; `repo_open`
            reads `[extensions] objectformat` from `.git/config`;
            `gut init --object-format=sha256` writes the extension and
            warns users that storage end-to-end is next.
      - [x] **Phase 2 storage**: loose objects use full-length hex paths
            (2/62), index format carries 32-byte OIDs with 32-byte trailer,
            refs store 64-hex, tree entries serialize 32-byte OIDs,
            `commit_parse` auto-detects hex width (40 or 64).
            **End-to-end verified**: `gut init --object-format=sha256 &&
            gut add && gut commit && gut log` produces a full SHA-256
            repo; every object at 64-hex path, HEAD ref 64-hex, commits
            reference 64-hex tree OIDs.
      - [x] **Phase 3 pack format**: `pack_hasher` helper (SHA-1 / SHA-256
            union); `pack_open_algo` and `pack_index_create_algo` thread
            algo through pack_idx_open, pack_idx_lookup, pack_read_object
            (REF_DELTA), pack_write trailer + idx, pack_index_create
            reconstruction. `odb_load_packs` now passes repo algo to
            pack_open. `cmd_repack` scans 2/62 loose paths with
            `oid_from_hex_n` and hex_len derived from repo algo; fixed
            `odb_resolve_prefix` pack-index walk and `cmd_log` parent
            copy (`sizeof(bytes)`) + `oid_to_hex_n`.
            **Verified**: multi-commit SHA-256 repo → `gut repack` writes
            pack-\<64hex\>.{pack,idx} with SHA-256 OIDs + 32-byte
            trailers; `gut log` walks full history via OFS_DELTA
            reconstruction from the pack.
      - [x] **Phase 4 wire**: smart HTTP `object-format=sha256` capability
            advertised in /info/refs; server + client hex widths derived
            from the active algo. Also `tree_parse_algo` (SHA-256 trees
            use 32-byte OIDs); threaded into srv closure walk, push walk,
            checkout read-tree, cat-file -p. `cmd_init --object-format
            sha256` and `gut clone` from a sha256 remote now write
            `repositoryformatversion = 1` so git accepts the config.
            **Verified interop**: `git clone http://<gut-server>/` over a
            sha256 repo pulls full history; `git push` back lands new
            commits which `gut log` reads correctly. `gut clone` from a
            `gut server` also works (fixed apennines http_response_parse
            to signal incomplete when Content-Length exceeds received
            body bytes — otherwise a header-sized first read breaks the
            tentative-parse loop with body_len=0).
- [x] Shallow clone — `gut clone --depth N`; writes `.git/shallow`; log walker respects boundary
- [x] Submodules — `.gitmodules` parser, gitfile (`.git` as text file)
      resolution in `repo_open`, mode-160000 skipped in index materialize,
      `gut clone --recurse-submodules` and `gut submodule update --init
      [--recursive]` fetch each submodule into `.git/modules/<name>/`
      and check out the pinned commit. SSH URLs (`git@host:path`) are
      cleanly skipped with a clear message since gut is http/https only.
      **Verified against VulpesIFF**: parent + `dependencies/VulpesCore`
      both materialize at the pinned OIDs that real `git clone
      --recursive` produces; `gut log` walks each submodule through the
      gitfile indirection.
- [x] Hooks — pre-commit / post-commit / pre-push; shebang-aware; `GUT_SKIP_HOOKS=1` bypass
- [x] `gut bisect` — linear-history binary search (MVP; merge-aware coming later)
- [x] Migrate build from CMake to `now` — `now.pasta` with
      `sources.include` listing all 32 vendored apennines files.
      Produces `target/bin/gut.exe` in one invocation. Verified end-
      to-end: init/add/commit/log, submodule clone of VulpesIFF pins
      VulpesCore at the expected OID. Built with 1.0.0-rc1 via
      `C:/Users/Iridium/Projects/now/build/static/bin/now.exe`.
