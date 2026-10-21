# Changelog

## 1.0.1 (2026-10-21)

Example and test-fixture repair against the `@aiyoplane/mcp-authz` 1.0+ public configuration contract. No change to the shipped adapter source (`src/`); the production adapter implementation is unchanged. The affected files were in the GitHub repository (`examples/minimal.js` and `test/adapter.test.js`) and were NOT included in the npm tarball — the `files` whitelist (`src/`, `README.md`, `LICENSE`, `NOTICE`) has never included `examples/` or `test/`. Adopters who installed `@aiyoplane/claude-agent-sdk` via `npm install` and wrote their own configuration are unaffected by the example-level defect; adopters who copied `examples/minimal.js` from GitHub as a starting point received a configuration whose shape the policy matcher does not read, which could leave the intended per-call policy ineffective even though the gate was invoked.

### Changed (test and example fixtures only)

- `toolConfig.<tool>.aiyoGated: true` → `aiyo_gated: true`. mcp-authz checks the snake_case key; the camelCase form was silently ignored, causing the tool to be treated as ungated and the Runtime Decision Point to be bypassed.
- Policy rules: top-level `action_type` moved under `rule.match.action_type`. mcp-authz's matcher reads `rule.match.action_type` against `intent.action.type`; the top-level form never matched any rule.
- Policy rules: `effect: 'block'` → `effect: 'deny'` to match mcp-authz's canonical ternary (`allow`/`escalate`/`deny`). `'block'` falls through to the deny fallback via `normalizeEffect`; using the canonical value makes the fixture unambiguous.
- `examples/minimal.js`: the policy previously used a non-canonical `path_prefix` field that mcp-authz's matcher does not read. The example now classifies the raw file path into a canonical `action.target` category (`tmp` / `etc` / `other`) via a top-level `intentBuilder` passed to `createAiyoMcpAuthz`, and the policy rules match on `rule.match.target`. This is the correct composition pattern when adopters want per-call policy discrimination derived from raw tool arguments.

### Added

- `test/policy-matching.test.js` — adapter-level behavioral conformance tests. ALLOW/DENY/ESCALATE path exercise plus boundary cases (`/tmp-evil/`, `/etcetera/`, `/TMP/`, `undefined`, `null`), effective-path consistency check, and a regression trip-wire that proves the broken-config state does not actually enforce per-path policy.
- `test/pattern-41-ordering.test.js` — Pattern 41 (Enforcement Before Irreversibility) ordering-invariant behavioral conformance. Eight vectors covering timing-ordering, BLOCK, fail-closed, ESCALATE, intentBuilder failure modes, concurrent-independent-decision, and the `wrapTool` form.
- `docs/EVIDENCE_PATTERN_41.md` — evidence record documenting the scenarios, mechanisms, and explicit non-claims.
- `test/regression-trip-wire-pre-repair.test.js` — negative-control test documenting the historical failure mode of the pre-1.0.1 broken example configuration. Pure mock handler; no filesystem, network, or subprocess calls. Reproduces the camelCase `aiyoGated` + top-level `action_type` + `path_prefix` + `effect: 'block'` shape and verifies that under that shape `@aiyoplane/mcp-authz@1.1.0` treats the tool as ungated and the handler is invoked on paths the author intended to prohibit. Also includes a contrast assertion confirming the repaired configuration correctly rejects `/etc/passwd`. This test documents an historical defect; it is not a specification of desired current behavior.
- `.github/workflows/ci.yml` — minimal CI running `node --test test/*.test.js` plus a `npm pack --dry-run` sanity check on push/PR, matrix across Node 20.x / 22.x / 24.x. Node 18 is end-of-life as of April 2025 and is not included in the CI matrix; the `engines.node` declaration remains `>=18.0.0` for this release — whether to raise the declared minimum is a separate deliberate support-policy decision.

### Not changed

- No change to `src/index.js`, `src/errors.js`, or any other shipped source file.
- No change to the npm tarball contents (`files` whitelist is unchanged: `src/`, `README.md`, `LICENSE`, `NOTICE`).
- No change to the published `@aiyoplane/claude-agent-sdk@1.0.0` artifact; adopters pinned to 1.0.0 continue to receive the exact same code.

## 1.0.0 (2026-10-05)

- Initial release.
- AEAP Composition Boundary Adapter for the Claude Agent SDK (Node).
- Entry points: `wrapToolHandler`, `wrapTool`.
- Positioned for coding-agent surfaces: file write, command execution, dependency install, git push, deploy.
- Fail-closed defaults per AEAP §2.2 invariant 5.
- Apache 2.0.
