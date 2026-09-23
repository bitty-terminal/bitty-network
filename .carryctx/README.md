# CarryCtx

<!-- carryctx:v1 -->

This directory stores versioned CarryCtx project configuration committed to Git.
It is safe to commit `.carryctx/` — it holds shared config, presets, and rules.

Runtime state (tasks, agents, events, sessions) lives in
`<git-common-dir>/carryctx/state.sqlite`, not in `.carryctx`.
Do not edit `state.sqlite` by hand; use `carryctx` commands or MCP tools.

- Repository: https://github.com/Xuepoo/carryctx
- Documentation: https://carryctx.xuepoo.xyz
  (see `carryctx-docs/configuration.md` for storage and XDG layout)
