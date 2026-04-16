# gut roadmap

## Completed

- [x] Core object model: blob, tree, commit, tag
- [x] SHA-1 hashing (own implementation)
- [x] Loose object store (zlib read/write)
- [x] Packfile reader (.idx v2, OFS_DELTA, REF_DELTA)
- [x] Index v2 binary format (read/write)
- [x] Repository init/open with parent walk
- [x] Ref management (branches, tags, HEAD)
- [x] Config reading (.git/config INI parser)
- [x] .gitignore with glob matching
- [x] Diff (patience algorithm, unified output)
- [x] Three-way merge (diff3 with conflict markers)
- [x] Short SHA prefix resolution
- [x] Full HTTPS client stack vendored (TLS 1.3, HTTP, crypto, PKI)

### Commands (21)
init, add, unstage, rm, branch, branches, tag, tags, checkout, merge,
diff, commit, log, status, last, amend, undo, restore, reset,
hash-object, cat-file

## In Progress

### Tier 3: Network Operations
- [ ] **gut clone** — smart HTTP ref discovery + pack download
- [ ] **gut fetch** — incremental pack negotiation (want/have)
- [ ] **gut push** — pack writer + send via git-receive-pack
- [ ] Remote tracking refs (origin/main, refs/remotes/)
- [ ] Remote config (.git/config [remote "origin"])

## Planned

### gut server
Self-hosted git-compatible server built on apennines http_server + tls.

- [ ] Smart HTTP endpoints: /info/refs, /git-upload-pack, /git-receive-pack
- [ ] Serve bare repositories
- [ ] Auth: bearer token, basic auth
- [ ] REST browse API: /repos, /commits, /tree (stretch)
- [ ] TLS with auto-cert or PEM loading

### gut link (real-time sync via WebSocket)
Persistent WSS connection between client and server for instant updates.

- [ ] `gut link <wss-url>` — establish connection, auto-fetch on ref changes
- [ ] Server broadcasts ref-update events on receive-pack
- [ ] Client auto-fetches new packs when notified
- [ ] Optional auto-checkout on clean fast-forward
- [ ] Terminal or system notification for new commits
- [ ] `gut unlink` — disconnect

### Quality of life
- [ ] `gut log --oneline` / `gut log --graph`
- [ ] `gut diff --stat`
- [ ] `gut stash` / `gut stash pop`
- [ ] `gut blame`
- [ ] `gut wip` — quick commit with [WIP] message
- [ ] `gut squash N` — squash last N commits
- [ ] `gut revert-file <commit> <path>` — restore single file from any commit
- [ ] Better error messages with context-aware suggestions

### Packfile writer
Needed for push and server; also enables `gut gc`.

- [ ] Delta computation (find similar objects, compute OFS_DELTA)
- [ ] Pack assembly (header + compressed objects + trailer)
- [ ] Pack index generation
- [ ] `gut gc` — repack loose objects

### Future
- [ ] SHA-256 object format option (modern git compat)
- [ ] Shallow clone (depth-limited fetch)
- [ ] Submodules
- [ ] Hooks (pre-commit, post-commit, pre-push)
- [ ] `gut bisect`
- [ ] Migrate build from CMake to `now`
