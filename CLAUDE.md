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
  diff, compress, net, async). Vendored at `lib/apennines/`. Bugs
  and features go to `to-apennines.md`; responses at
  `from-apennines.md`.
- **now** — build system (1.0.0-rc1). Ships our builds. Migration
  guide at `C:/Users/Iridium/Projects/now/docs/migration-guide.md`.
  Mailbox files: `to-now.md` / `from-now.md`.
- **cookbook** — registry/server for built artifacts. We don't
  interact heavily but they share the mailbox.
- **pasta** — the project descriptor format now reads. Shared INI/JSON-like
  config language.

See [knowledge-transfer.md](./knowledge-transfer.md) for:
- Full architecture and module map
- Code conventions (calling convention, error hatches, naming)
- SHA-256 phase design (all 4 phases shipped)
- Pack writer / delta encoder design (path-hint sort, basename clustering)
- REST browse API
- Test recipes and bench methodology

## Roadmap

- [roadmap.md](./roadmap.md) — Tier 1-3 all green. **Tier 4 (full
  drop-in git replacement)** is the next horizon: SSH transport,
  interactive rebase, cherry-pick, reflog, worktree add, partial
  clone `--filter`, credential helpers.

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
