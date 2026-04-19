# gut — session context

This file is auto-loaded at the start of every Claude Code session in
this project. It's a short orientation; deeper context lives in
[knowledge-transfer.md](./knowledge-transfer.md).

## What gut is

A clean reimplementation of git in C11 with vendored dependencies.
Serves as the foundation for the team's native toolchain ecosystem
(gut, apennines, now, cookbook, pasta). Interoperates with real git
bit-for-bit on the wire and on disk; extends the protocol with a P2P
ambient-awareness layer (listen/leech/ask/offer/sos/feeling).

45+ commands, SHA-1 + SHA-256 both fully supported, TLS 1.3,
submodules, shallow clone, hooks, bisect, now-based build.

## Build

```
C:/Users/Iridium/Projects/now/build/static/bin/now.exe build
```

Requires MinGW gcc on PATH:

```
export PATH="/c/Program Files/JetBrains/CLion 2025.3.3/bin/mingw/bin:$PATH"
```

Output at `target/bin/gut.exe`. CMakeLists.txt also present (kept for
IDE integration) — either build system works.

**Gotcha**: if `gut.exe` was recently run, Windows file locks prevent
the linker from overwriting it. Run `taskkill //F //IM gut.exe` before
rebuilding.

## Peer teams

gut coordinates with four sibling projects via an async mailbox at
`~/.claude/mailbox/`:

- **apennines** — runtime library (HTTP, HTTPS, TLS, crypto, buf,
  diff, compress, net, async, SSH client + known_hosts). Vendored at
  `lib/apennines/`. Bugs and features go to `to-apennines.md`;
  responses at `from-apennines.md`. Heavy collaborator — they ship
  primitives fast when we flag a need. Eight SSH iterations
  (000120→000131) happened over one evening in April 2026.
- **now** — build system (1.0.0-rc1). Ships our builds. Migration
  guide at `C:/Users/Iridium/Projects/now/docs/migration-guide.md`.
  Mailbox files: `to-now.md` / `from-now.md`.
- **cookbook** — registry/server for built artifacts. We don't
  interact heavily but they share the mailbox.
- **pasta** — the project descriptor format now reads. Shared INI/JSON-like
  config language.

### Mailbox protocol (quick reference)

Full spec: `~/.claude/mailbox/interconnection-protocol.md`.

**File layout** per peer pair:

```
~/.claude/mailbox/
  from-gut.md         ← we append here for broadcasts
  to-gut.md           ← peers append here; our inbox
  from-apennines.md   ← apennines appends; we read
  to-apennines.md     ← we append here for directed requests
  from-now.md / to-now.md / from-cookbook.md / to-cookbook.md
```

Directed traffic goes in the destination's `to-<peer>.md`;
broadcasts we want every peer to see go in our `from-gut.md`.
Major announcements typically land in both.

**Message format** (append-only markdown, one topic per message):

```
### [YYYY-MM-DD HH:MM] TOPIC — short summary

Status: INFO | REQUEST | RESPONSE | ACK
Re: (optional — quote or reference the message being responded to)

Body text. Keep concise. Include what was done / what is needed,
relevant file paths / API signatures, blockers or dependencies.

— gut
```

**Status types**:
- `INFO` — broadcasting state; no response required (ACK appreciated)
- `REQUEST` — asking for something; expects `RESPONSE`
- `RESPONSE` — answering a prior `REQUEST` (cite with `Re:`)
- `ACK` — "seen and noted" — closes a thread

**Handoff folder** for transferring code for absorption:
`~/.claude/mailbox/gut-for-apennines/` (and mirrors for other peers).
Used for known_hosts absorption in April 2026; the receiving peer
picks files up and clears the folder once integrated.

**Check cadence**: no polling. We check when the user says
"mailbox", at the start of a new session if the user references a
pending thread, or when we're mid-thread waiting on a response and
expect one shortly.

**UTC for timestamps**. Use `date -u '+%Y-%m-%d %H:%M'` before
composing a message header.

**Reading tip**: mailbox files grow — use
`tail -NN /c/Users/Iridium/.claude/mailbox/to-gut.md` and
`grep -n "^### \[" ...` to locate recent messages rather than
reading the whole file.

See [knowledge-transfer.md](./knowledge-transfer.md) for:
- Full architecture and module map
- Code conventions (calling convention, error hatches, naming)
- SHA-256 phase design (all 4 phases shipped)
- Pack writer / delta encoder design (path-hint sort, basename clustering)
- REST browse API
- Test recipes and bench methodology

## Roadmap

- [roadmap.md](./roadmap.md) — Tier 1-3 all green. **Tier 4 ~87%
  shipped** as of April 2026: SSH transport + host-key pinning,
  reflog, cherry-pick, non-interactive + interactive rebase
  (pick/drop/squash/fixup/reword), worktree add + list, credential
  helpers with HTTPS 401 auto-retry. **Remaining Tier 4:** partial
  clone `--filter=blob:none` / `--filter=tree:0` (promisor-remote
  config + lazy object fetch + `pack_index.v3`-style missing-object
  markers). **Tier 5 spec'd in roadmap:** drop-copy audit channel
  (non-destructive mirror, dual-channel attestation, cold-pack
  time-bucket consolidation, glacier tier with SHA-256 hash stubs).

## Session conventions

- Use `TodoWrite`/`TaskCreate` for multi-step work.
- Before a risky action (force-push, `rm -rf`, destructive git), confirm.
- Error messages use the "line-number hatch" idiom — `return __LINE__`
  and user-facing messages print `(line 123)`. Don't strip these.
- Every function in our own code returns `unsigned long` (0 = success,
  non-zero = line-of-failure). First parameter is the output; rest are
  inputs. Match the apennines style even when modifying gut.
- Types: use `u8/u16/u32/u64/i8/i16/i32/i64/f32/f64` aliases from
  apennines; avoid raw int/long/size_t in new code.
- Naming: `module_operation` — `pack_write`, `tree_parse_algo`,
  `submodules_update_all`.
