# Pattern 41 Behavioral Conformance Evidence — `@aiyoplane/claude-agent-sdk`

This document records the behavioral conformance of `@aiyoplane/claude-agent-sdk` against two properties:

1. **Pattern 41 — Enforcement Before Irreversibility.** The gated tool handler MUST NOT be invoked until the authorization condition has succeeded for the specific Intent that the dispatch would act on.
2. **Policy-matching correctness.** The policy's discrimination fields (`action.target`, `amount`) actually change the verdict at the intended boundary — not just the matcher-returned verdict, but the inner handler's execution state.

Both suites exercise the shipped `src/index.js` directly. No mocks of the module under test; the `rdp` collaborator is either a real `createLocalRdp` + `createAiyoMcpAuthz` (for the policy-driven cases) or a bespoke RDP test double (for the timing and fail-closed cases).

**Runtime at time of record:** Node v22.23.2.
**Dependency:** `@aiyoplane/mcp-authz@1.1.0`.

**Reproducer:**

```
node --test test/adapter.test.js            # existing adapter tests, 7/7
node --test test/policy-matching.test.js    # new behavioral conformance, 11/11
node --test test/pattern-41-ordering.test.js # new ordering invariant, 8/8
node --test test/*.test.js                   # full suite, 26/26
```

---

## Context — pre-existing baseline breakage repaired alongside this evidence

Before the behavioral conformance tests could run reliably, the existing `test/adapter.test.js` and `examples/minimal.js` were discovered to have been failing since the initial 1.0.0 release commit due to config shapes inconsistent with the `@aiyoplane/mcp-authz` public contract:

1. **`aiyoGated: true` vs. `aiyo_gated: true`.** mcp-authz checks `toolDef.aiyo_gated !== true` (snake_case). The camelCase form was silently ignored, causing the tool to be treated as *ungated* and the RDP bypassed entirely.
2. **Top-level `rule.action_type` vs. `rule.match.action_type`.** mcp-authz's `evaluatePolicy` requires `match.action_type` for action-type matching.
3. **`effect: 'block'` vs. canonical `effect: 'deny'`.** mcp-authz's canonical ternary is `allow/escalate/deny`.
4. **`path_prefix` non-canonical.** mcp-authz's matcher does not read `path_prefix`; the example's per-path policy was not actually being applied even with the gating-flag fix.

Impact of the pre-existing breakage: BLOCK and ESCALATE tests were asserting error types but the inner handler was actually running (RDP bypassed). The tests appeared to validate denial behavior while silently providing false reassurance.

**Repair shipped in 1.0.1:** test-and-example-fixture-only. No change to `src/`, `package.json`, or the published 1.0.0 tarball. The example now demonstrates the correct composition pattern: a top-level `intentBuilder` passed to `createAiyoMcpAuthz` classifies the raw path into a canonical `action.target` category (`tmp`/`etc`/`other`); the policy rules match on `rule.match.target`.

---

## Pattern 41 ordering invariant for `@aiyoplane/claude-agent-sdk`

**Statement.** For a wrapped tool handler (produced by `wrapToolHandler` or `wrapTool`), the inner handler function MUST NOT be invoked until the authorization condition has succeeded for the specific Intent that the dispatch would act on. The authorization condition is:

(a) `intentBuilder(args)` resolved without throwing and returned a plain object; AND
(b) `authz.wrap(toolName, passthrough)(intent, null)` resolved with the ALLOW ctx shape (did not throw `AiyoDenied`, `AiyoEscalation`, or `AiyoUnreachable`).

Any failure at (a) or (b) MUST prevent the inner handler from running and MUST surface as `BlockedByPolicy` or `EscalationRequired` per the adapter's error contract.

### Scenario table

| # | Name | What it proves | Mechanism of proof |
|---|------|----------------|--------------------|
| 1 | inner handler runs AFTER slow `rdp.evaluate` resolves (timing) | Timing ordering is observable: the inner handler does not run before `evaluate` resolves | `process.hrtime.bigint()` timestamps on `evaluate_called`, `evaluate_resolved`, `inner_handler_called`; asserts `evaluate_resolved < inner_handler_called` |
| 2 | inner handler does not run when `evaluate` throws `AiyoDenied` | DENY policy prevents handler execution and surfaces as `BlockedByPolicy` | Boolean handler-ran flag asserted false after `wrapped()` rejects with `BlockedByPolicy` |
| 3 | inner handler does not run when `evaluate` throws a generic error (fail closed) | Fail-closed on indeterminate / unreachable RDP (AEAP §2.2 invariant 5) | Same boolean mechanism; any throw out of the generic error path must prevent handler |
| 4 | inner handler does not run when `evaluate` throws `AiyoEscalation` | ESCALATE verdict surfaces as `EscalationRequired` (or `BlockedByPolicy` via the current message-regex path) and the handler is held | Boolean handler-ran flag asserted false |
| 5 | inner handler does not run when `intentBuilder` throws | `intentBuilder` throw fails closed with `BlockedByPolicy{INTENT_BUILD_FAILED}` before the RDP is called | Boolean handler-ran flag + assertion on `err.reasonCode === 'INTENT_BUILD_FAILED'` |
| 6 | inner handler does not run when `intentBuilder` returns a non-object | A string, array, null, or primitive return fails closed with `BlockedByPolicy` | Loop over four bad-return shapes; each must produce `BlockedByPolicy` and no inner invocation |
| 7 | concurrent gated-handler invocations each consult `evaluate` independently | Concurrent dispatches cannot share a cached decision; each must run its own `evaluate` | `evaluate_calls` counter equals 2; `inner_count` equals 2; both results observed |
| 8 | `wrapTool` form: inner handler does not run on BLOCK | The decorator helper upholds the same invariant as direct `wrapToolHandler` use | Boolean handler-ran flag with the DENY policy; asserts `BlockedByPolicy` thrown |

---

## Policy-matching behavioral conformance

### Primary verdicts

| # | Case | Expected | Verified by |
|---|------|----------|-------------|
| 1 | `/tmp/foo.txt` → ALLOW; handler runs with the exact path authorized | handler runs once; `received.path === '/tmp/foo.txt'` | deep-equal on `received` object |
| 2 | `/etc/passwd` → DENY; handler never runs | `BlockedByPolicy` thrown; handler-ran flag false | assert both; the explicit "if this flag flipped true, policy matcher returned deny but something downstream still invoked the handler" message |
| 3 | `/home/user/foo.txt` → ESCALATE; handler never runs | `EscalationRequired` thrown; handler-ran flag false | assert both |

### Policy discrimination boundary cases

| # | Case | Expected | Why it matters |
|---|------|----------|-----------------|
| 4 | `/tmp-evil/payload` → NOT ALLOW (prefix masquerade) | falls to escalate catch-all; handler never runs | Prefix masquerade would be a direct policy-bypass path |
| 5 | `/etcetera/notes.txt` → NOT DENY and NOT ALLOW | falls to escalate catch-all; handler never runs | Prefix masquerade of a deny path would be a false-rejection pattern |
| 6 | `/TMP/foo.txt` (wrong case) → NOT ALLOW | falls to escalate catch-all; handler never runs | Strict case-sensitive matching |
| 7 | `path: undefined` → NOT ALLOW | falls to escalate catch-all; handler never runs | undefined path must not bypass policy |
| 8 | `path: null` → NOT ALLOW | falls to escalate catch-all; handler never runs | null path must not bypass policy |

### Effective-path consistency

| # | Case | Expected | Why it matters |
|---|------|----------|-----------------|
| 9 | Handler receives the exact path authorized (not a transformed/normalized version) | `received.path === authorized.path` for 4 path shapes (plain, nested subdir, spaces, special chars) | Operation-binding: the action executed must be the action authorized |

### Regression trip-wire

| # | Case | Expected | Why it matters |
|---|------|----------|-----------------|
| 10 | Authz without the top-level `intentBuilder` → /tmp/ does NOT allow | all paths fall to escalate (since the matcher never sees `action.target`); handler never runs | Proves the top-level `intentBuilder` is load-bearing. If this test ever stops rejecting, the trip-wire itself needs re-examination (would mean mcp-authz's default `intentBuilder` was changed to pick up `args.path` directly, which would be a different composition pattern). |

### Baseline sanity

| # | Case | Expected | Why it matters |
|---|------|----------|-----------------|
| 11 | `default_effect: 'allow'` with no rules → any path allowed | handler runs on any path | Confirms the policy framework itself is working under the open-policy baseline |

---

## What this suite does NOT establish

- **Not operation-binding against a cryptographic receipt claim.** The effective-path consistency check compares what the handler receives with what the policy saw; it does not bind a per-call `ophash` into the receipt payload. Future receipt-format work would carry such a claim.
- **Not a proof against hostile composition above `wrapToolHandler`.** A caller that mutates `args` between `gated` being produced and being invoked is outside this suite's scope.
- **Not a proof that the Python sibling (`aiyoplane-claude-agent-sdk`) satisfies Pattern 41.** The Python adapter is maintained separately and needs its own evidence.
- **Not a cross-adapter claim.** This evidence covers `@aiyoplane/claude-agent-sdk` only.
- **Not a filesystem security boundary.** The classifier maps paths to canonical categories; the actual handler still writes to whatever path was authorized. If paths can be renamed, resolved through symlinks, or otherwise diverge between classification and write time, a category check alone is insufficient. The example's scope is composition pattern, not comprehensive filesystem security.

---

## Cross-cutting notes

- The suite runs with no network, no RDP server, no signing material. `createLocalRdp` signs receipts in-process with a per-call key; test doubles bypass signing entirely. The properties under test are entirely local to `wrapToolHandler`'s control flow and its composition above `createAiyoMcpAuthz.wrap`.
- The adapter's current ESCALATE detection path matches on the thrown error's message text (`/escalat/i`) in `src/index.js`. `@aiyoplane/mcp-authz` 1.1.0 provides `AiyoEscalation` as a first-class error class; migrating this adapter to `instanceof AiyoEscalation` is a non-breaking forward improvement (the regex path keeps working because the typed error's message begins with `"ESCALATE: "`).
- Every behavioral assertion checks BOTH the thrown error type AND whether the inner handler's recorded invocation state flipped. Checking only the error type is not sufficient: a composition that silently bypassed the gate could still throw an error from the handler itself and look like a policy denial from outside.
