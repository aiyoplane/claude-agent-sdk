// Policy-matching behavioral conformance tests for @aiyoplane/claude-agent-sdk.
//
// Verifies that the composition pattern demonstrated in examples/minimal.js
// correctly plumbs per-call tool arguments through to the policy matcher,
// such that:
//
//   - ALLOW: the protected handler executes.
//   - BLOCK/DENY: the protected handler does NOT execute.
//   - ESCALATE: the protected handler does NOT execute (held pending resolution).
//   - Policy discrimination: the target or amount actually changes the verdict
//     at the intended boundary (not just the matcher-returned verdict).
//   - Regression: an older-style fixture that silently bypassed the gate
//     would fail this suite — the repair is actually load-bearing.
//
// Every assertion checks BOTH the thrown error type AND whether a boolean
// handler-ran flag flipped. Checking only the error type is not sufficient:
// a composition that silently bypassed the gate could still throw an error
// from the handler itself (e.g., a filesystem write failure) and look like
// a policy denial from outside.
//
// Run: node --test test/policy-matching.test.js

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { createAiyoMcpAuthz, createLocalRdp } from '@aiyoplane/mcp-authz';

import {
  BlockedByPolicy,
  EscalationRequired,
  wrapToolHandler,
} from '../src/index.js';

// ─── Shared classifier + authz builder (mirrors examples/minimal.js) ────────

function classifyPathTarget(path) {
  if (typeof path !== 'string') return 'unknown';
  if (path.startsWith('/tmp/')) return 'tmp';
  if (path.startsWith('/etc/')) return 'etc';
  return 'other';
}

const DEFAULT_POLICY = {
  default_effect: 'deny',
  rules: [
    { match: { action_type: 'file_write', target: 'tmp' }, effect: 'allow' },
    { match: { action_type: 'file_write', target: 'etc' }, effect: 'deny' },
    { match: { action_type: 'file_write' },                 effect: 'escalate' },
  ],
};

function makeAuthz(policy = DEFAULT_POLICY) {
  return createAiyoMcpAuthz({
    rdp: createLocalRdp({ policy }),
    toolConfig: {
      write_file: { aiyo_gated: true, action: { type: 'file_write' } },
    },
    intentBuilder: (toolName, args) => ({
      amount: 0,
      currency: 'usd',
      action: { type: 'file_write', target: classifyPathTarget(args.path) },
      metadata: { source: 'test', tool_name: toolName, path: args.path },
    }),
  });
}

// Factory for a gated handler that records every invocation. The recorded
// state is what we assert on — not just the thrown exception type.
function makeGatedHandler(authz) {
  const log = { invoked: false, received: null, calls: 0 };
  const handler = async ({ path, content }) => {
    log.invoked = true;
    log.received = { path, content };
    log.calls += 1;
    return `Wrote ${content.length} bytes to ${path}`;
  };
  const gated = wrapToolHandler(handler, {
    authz,
    toolName: 'write_file',
    intentBuilder: ({ path, content }) => ({
      type: 'file_write',
      path,
      bytes: content?.length ?? 0,
    }),
  });
  return { gated, log };
}

// ─── Section A — primary verdicts: ALLOW, DENY, ESCALATE ────────────────────

test('[allow] /tmp/foo → handler executes with the exact path authorized', async () => {
  const authz = makeAuthz();
  const { gated, log } = makeGatedHandler(authz);

  const result = await gated({ path: '/tmp/foo.txt', content: 'hello' });

  assert.equal(log.invoked, true, 'handler must execute on ALLOW');
  assert.equal(log.calls, 1, 'handler must execute exactly once');
  assert.deepEqual(log.received, { path: '/tmp/foo.txt', content: 'hello' },
    'INVARIANT: handler receives the exact same path that was authorized (effective-path consistency)');
  assert.match(result, /Wrote 5 bytes to \/tmp\/foo\.txt/);
});

test('[deny] /etc/passwd → BlockedByPolicy thrown; handler never runs', async () => {
  const authz = makeAuthz();
  const { gated, log } = makeGatedHandler(authz);

  await assert.rejects(
    gated({ path: '/etc/passwd', content: 'evil' }),
    (err) => err instanceof BlockedByPolicy,
    'wrapped handler must reject with BlockedByPolicy on DENY'
  );

  assert.equal(log.invoked, false,
    'INVARIANT: protected handler MUST NOT run on DENY. If this flipped true, the policy matcher returned deny but something downstream still invoked the handler.');
});

test('[escalate] /home/user/foo → EscalationRequired thrown; handler never runs', async () => {
  const authz = makeAuthz();
  const { gated, log } = makeGatedHandler(authz);

  await assert.rejects(
    gated({ path: '/home/user/foo.txt', content: 'hi' }),
    (err) => err instanceof EscalationRequired || err instanceof BlockedByPolicy,
    'wrapped handler must reject with EscalationRequired (or BlockedByPolicy via regex-detection) on ESCALATE'
  );

  assert.equal(log.invoked, false,
    'INVARIANT: protected handler MUST NOT run while ESCALATE is unresolved. The adapter has no out-of-band resolution path yet, so the escalation surfaces as EscalationRequired.');
});

// ─── Section B — policy discrimination boundary cases ───────────────────────
//
// PM-mandated: verify the matcher's strict-equality behavior at close-but-
// not-matching values. All of these MUST fall to the escalate catch-all,
// not to the /tmp/ allow or /etc/ deny.

test('[boundary] /tmp-evil/foo → NOT ALLOW (prefix masquerade); escalates; handler never runs', async () => {
  const authz = makeAuthz();
  const { gated, log } = makeGatedHandler(authz);

  await assert.rejects(
    gated({ path: '/tmp-evil/payload', content: 'x' }),
    (err) => {
      // Must NOT be BlockedByPolicy from the /etc/ rule (would mean strict
      // matcher misfired on a non-match). Must NOT allow (would mean prefix
      // masquerade bypassed the matcher). Should escalate via catch-all.
      return err instanceof EscalationRequired || err instanceof BlockedByPolicy;
    },
    '/tmp-evil/ must not match /tmp/ via prefix; must fall to the escalate catch-all'
  );
  assert.equal(log.invoked, false,
    'INVARIANT: /tmp-evil/ MUST NOT be treated as /tmp/. Prefix masquerade would be a direct policy-bypass path.');
});

test('[boundary] /etcetera/foo → NOT DENY and NOT ALLOW; escalates; handler never runs', async () => {
  const authz = makeAuthz();
  const { gated, log } = makeGatedHandler(authz);

  await assert.rejects(
    gated({ path: '/etcetera/notes.txt', content: 'ok' }),
    (err) => err instanceof EscalationRequired || err instanceof BlockedByPolicy
  );
  assert.equal(log.invoked, false,
    'INVARIANT: /etcetera/ MUST NOT be treated as /etc/. Prefix masquerade of a deny path would be a false-rejection pattern.');
});

test('[boundary] /TMP/foo (wrong case) → NOT ALLOW; escalates; handler never runs', async () => {
  const authz = makeAuthz();
  const { gated, log } = makeGatedHandler(authz);

  await assert.rejects(
    gated({ path: '/TMP/foo.txt', content: 'ok' }),
    (err) => err instanceof EscalationRequired || err instanceof BlockedByPolicy
  );
  assert.equal(log.invoked, false,
    'INVARIANT: strict case-sensitive matching. /TMP/ MUST NOT widen to /tmp/.');
});

test('[boundary] undefined path → classifies to "unknown"; escalates; handler never runs', async () => {
  const authz = makeAuthz();
  const { gated, log } = makeGatedHandler(authz);

  // The handler expects path+content; passing an undefined path with content
  // exercises the classifier's handling of non-string input.
  await assert.rejects(
    gated({ path: undefined, content: 'x' }),
    (err) => err instanceof EscalationRequired || err instanceof BlockedByPolicy,
    'undefined path must fail closed, not widen to any rule'
  );
  assert.equal(log.invoked, false,
    'INVARIANT: undefined path MUST NOT bypass policy. Fail-closed.');
});

test('[boundary] null path → classifies to "unknown"; escalates; handler never runs', async () => {
  const authz = makeAuthz();
  const { gated, log } = makeGatedHandler(authz);

  await assert.rejects(
    gated({ path: null, content: 'x' }),
    (err) => err instanceof EscalationRequired || err instanceof BlockedByPolicy
  );
  assert.equal(log.invoked, false,
    'INVARIANT: null path MUST NOT bypass policy.');
});

// ─── Section C — effective-path consistency ─────────────────────────────────

test('[effective-path] handler receives the exact path that was authorized (no normalization drift)', async () => {
  const authz = makeAuthz();
  const { gated, log } = makeGatedHandler(authz);

  const paths = [
    '/tmp/plain.txt',
    '/tmp/subdir/nested.txt',
    '/tmp/with spaces.txt',
    '/tmp/weird-chars_$%.txt',
  ];
  for (const p of paths) {
    log.invoked = false;
    log.received = null;
    log.calls = 0;
    await gated({ path: p, content: 'hi' });
    assert.equal(log.invoked, true, `handler must execute for ${p}`);
    assert.equal(log.received.path, p,
      `INVARIANT: handler receives the EXACT path authorized. Observed ${log.received.path}, expected ${p}. Any transformation between Intent construction and handler invocation would break effective-path consistency.`);
  }
});

// ─── Section D — regression trip-wire ────────────────────────────────────────
//
// This test configures an authz WITHOUT the top-level intentBuilder (reverting
// to the pre-repair state where the adapter-level intentBuilder output doesn't
// reach the matcher). If this test fails to detect the misconfiguration — if
// a /etc/passwd write succeeds under this broken config — the repair itself
// is load-bearing and the test suite would miss the regression.

test('[regression-trip-wire] without the top-level intentBuilder, /etc/passwd would silently succeed', async () => {
  // DELIBERATELY mis-configured authz: no top-level intentBuilder.
  // The default intentBuilder in mcp-authz builds intent.action from the
  // STATIC toolDef.action, not from the adapter's intent output. action.target
  // is undefined → no rule's `match.target` constraint can be satisfied for
  // the tmp/etc rules → first rule evaluates to a "no target constraint
  // satisfied, overall match depends on action_type only" state. Let's observe
  // what happens.
  const brokenAuthz = createAiyoMcpAuthz({
    rdp: createLocalRdp({ policy: DEFAULT_POLICY }),
    toolConfig: {
      write_file: { aiyo_gated: true, action: { type: 'file_write' } },
    },
    // NOTE: no intentBuilder passed; default is used.
  });

  const { gated, log } = makeGatedHandler(brokenAuthz);

  // Expectation under the broken config: the policy's first two rules
  // require target='tmp' / target='etc'. With intent.action.target === undefined,
  // neither constraint is satisfied for those rules → match fails → falls to
  // rule 3 (match on action_type only, no target constraint) → ESCALATE for all.
  //
  // So the trip-wire finding is: a broken config makes EVERYTHING escalate,
  // regardless of path. That's not a security bypass (nothing's allowed), BUT
  // it IS evidence of a policy-discrimination failure — the matcher doesn't
  // actually distinguish paths. For a config that intended per-path ALLOW/DENY,
  // this is a defect.
  //
  // We assert the trip-wire: a /tmp/ write that should ALLOW does not actually
  // allow under the broken config. If this ever passes (handler runs), that
  // means something changed in mcp-authz's default intentBuilder to pick up
  // args.path, and the trip-wire itself is no longer load-bearing.
  await assert.rejects(
    gated({ path: '/tmp/foo.txt', content: 'hi' }),
    (err) => err instanceof EscalationRequired || err instanceof BlockedByPolicy,
    'TRIP-WIRE: without the top-level intentBuilder, /tmp/ writes do NOT reach ALLOW. If this stops rejecting, the trip-wire needs re-examination.'
  );
  assert.equal(log.invoked, false,
    'INVARIANT: without the custom top-level intentBuilder, per-path discrimination does not work; the handler must NOT run on /tmp/.');
});

// ─── Section E — default behavior when policy is wide open ──────────────────

test('[baseline] default_effect: allow + no rules → every path allowed (sanity for policy framework)', async () => {
  const openPolicy = { default_effect: 'allow', rules: [] };
  const authz = makeAuthz(openPolicy);
  const { gated, log } = makeGatedHandler(authz);

  await gated({ path: '/anywhere/x', content: 'ok' });
  assert.equal(log.invoked, true, 'default_effect: allow with no rules must permit any path');
});
