// Pattern 41 (Enforcement Before Irreversibility) ordering invariant —
// @aiyoplane/claude-agent-sdk conformance tests.
//
// Verifies the shipped @aiyoplane/claude-agent-sdk code does not permit a
// wrapped tool handler to run before the required authorization condition
// is satisfied. The gated unit is a tool handler (args) → result; wrapToolHandler
// composes above mcp-authz's authz.wrap(toolName, passthrough).
//
// Ordering invariant for the adapter:
//
//   For a wrapped tool handler (produced by wrapToolHandler or wrapTool), the
//   underlying handler function MUST NOT be invoked until the authorization
//   condition has succeeded for the specific Intent that the gated-handler
//   dispatch would act on. The authorization condition is:
//     (a) intentBuilder(args) resolved without throwing and returned a
//         plain object; AND
//     (b) authz.wrap(toolName, passthrough)(intent, null) resolved with the
//         ALLOW ctx shape (did not throw AiyoDenied, AiyoEscalation, or
//         AiyoUnreachable).
//
//   Any failure at (a) or (b) MUST prevent the handler from running and
//   MUST surface as BlockedByPolicy or EscalationRequired per the adapter's
//   error contract.
//
// Eight behavioral cases below. Each would fail LOUDLY if the invariant
// breaks — not from source inspection, but from observing whether the
// handler's recorded invocation happened.
//
// Run:  node --test test/pattern-41-ordering.test.js

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { createAiyoMcpAuthz, createLocalRdp } from '@aiyoplane/mcp-authz';

import {
  AdapterConfigError,
  BlockedByPolicy,
  EscalationRequired,
  wrapToolHandler,
  wrapTool,
} from '../src/index.js';

// Helper: build an authz backed by createLocalRdp with a single-rule policy.
function makeAuthz(ruleEffect, extra = {}) {
  return createAiyoMcpAuthz({
    rdp: createLocalRdp({
      policy: {
        default_effect: 'deny',
        rules: [{
          id: 'pattern-41-vector',
          match: { action_type: 'file_write' },
          effect: ruleEffect,
          ...extra,
        }],
      },
    }),
    toolConfig: {
      write_file: { aiyo_gated: true, action: { type: 'file_write' } },
    },
    verifyReceiptOnAllow: false,
  });
}

// Helper: build an authz backed by a bespoke RDP double.
function makeAuthzWithRdp(rdpDouble) {
  return createAiyoMcpAuthz({
    rdp: rdpDouble,
    toolConfig: {
      write_file: { aiyo_gated: true, action: { type: 'file_write' } },
    },
    verifyReceiptOnAllow: false,
  });
}

const intentBuilder = ({ path }) => ({ type: 'file_write', path });

// ─── Case 1 — ALLOW happy path with latency ─────────────────────────────

test('[release-blocker] inner handler runs AFTER slow rdp.evaluate resolves (timing)', async () => {
  const events = [];
  const record = (name) => events.push({ name, t: process.hrtime.bigint() });

  const rdp = {
    async evaluate() {
      record('evaluate_called');
      await new Promise((r) => setTimeout(r, 50));
      record('evaluate_resolved');
      return {
        intentId: 'test-intent-1',
        receipt: { token: 'v2.fake.sig' },
        decision: { verdict: 'ALLOW' },
      };
    },
    async close() {},
    async verifyReceipt() { return { iid: 'test-intent-1' }; },
  };

  const innerHandler = async ({ path }) => {
    record('inner_handler_called');
    return `wrote ${path}`;
  };

  const gated = wrapToolHandler(innerHandler, {
    authz: makeAuthzWithRdp(rdp),
    toolName: 'write_file',
    intentBuilder,
  });

  const result = await gated({ path: '/tmp/foo' });
  record('gated_returned');

  const t = (name) => events.find((e) => e.name === name)?.t;

  assert.ok(t('evaluate_called') !== undefined, 'evaluate must have been called');
  assert.ok(t('evaluate_resolved') !== undefined, 'evaluate must have resolved');
  assert.ok(t('inner_handler_called') !== undefined, 'inner handler must have been called on ALLOW');
  assert.ok(
    t('evaluate_resolved') < t('inner_handler_called'),
    'INVARIANT VIOLATION: inner handler ran before evaluate resolved. Pattern 41 ordering failure at the claude-agent-sdk composition boundary.'
  );
  assert.equal(result, 'wrote /tmp/foo');
});

// ─── Case 2 — BLOCK path via AiyoDenied ─────────────────────────────────

test('[release-blocker] inner handler does not run when evaluate throws AiyoDenied', async () => {
  let inner_called = false;

  const authz = makeAuthz('deny');
  const gated = wrapToolHandler(
    async () => {
      inner_called = true;
      return 'ran';
    },
    { authz, toolName: 'write_file', intentBuilder }
  );

  await assert.rejects(
    () => gated({ path: '/tmp/foo' }),
    (err) => err instanceof BlockedByPolicy,
    'wrapped handler must reject with BlockedByPolicy on policy deny'
  );

  assert.equal(
    inner_called,
    false,
    'INVARIANT VIOLATION: inner handler ran despite DENY. Pattern 41 ordering failure on the BLOCK path.'
  );
});

// ─── Case 3 — Generic throw (fail-closed) ───────────────────────────────

test('[release-blocker] inner handler does not run when evaluate throws a generic error (fail closed)', async () => {
  let inner_called = false;

  const rdp = {
    async evaluate() {
      const err = new Error('network partition');
      err.code = 'UNAVAILABLE';
      throw err;
    },
    async close() {},
    async verifyReceipt() { throw new Error('unreachable'); },
  };

  const gated = wrapToolHandler(
    async () => {
      inner_called = true;
      return 'ran';
    },
    { authz: makeAuthzWithRdp(rdp), toolName: 'write_file', intentBuilder }
  );

  await assert.rejects(() => gated({ path: '/tmp/foo' }), (_err) => true);
  assert.equal(
    inner_called,
    false,
    'INVARIANT VIOLATION: inner handler ran despite evaluate throwing. Fail-closed invariant breached.'
  );
});

// ─── Case 4 — ESCALATE path via AiyoEscalation ──────────────────────────

test('[release-blocker] inner handler does not run when evaluate throws AiyoEscalation', async () => {
  let inner_called = false;

  const authz = makeAuthz('escalate', { escalation_id: 'approve-wf-1' });
  const gated = wrapToolHandler(
    async () => {
      inner_called = true;
      return 'ran';
    },
    { authz, toolName: 'write_file', intentBuilder }
  );

  await assert.rejects(
    () => gated({ path: '/tmp/foo' }),
    (err) => err instanceof EscalationRequired || err instanceof BlockedByPolicy,
    'wrapped handler must reject with EscalationRequired (or BlockedByPolicy via regex-detection) on policy escalate'
  );

  assert.equal(
    inner_called,
    false,
    'INVARIANT VIOLATION: inner handler ran despite ESCALATE. Pattern 41 ordering failure on the ESCALATE path.'
  );
});

// ─── Case 5 — intentBuilder throws ──────────────────────────────────────

test('[release-blocker] inner handler does not run when intentBuilder throws', async () => {
  let inner_called = false;

  const gated = wrapToolHandler(
    async () => {
      inner_called = true;
      return 'ran';
    },
    {
      authz: makeAuthz('allow'),
      toolName: 'write_file',
      intentBuilder: () => {
        throw new Error('intent build failed deliberately');
      },
    }
  );

  await assert.rejects(
    () => gated({ path: '/tmp/foo' }),
    (err) => err instanceof BlockedByPolicy && err.reasonCode === 'INTENT_BUILD_FAILED',
    'wrapped handler must reject with BlockedByPolicy{INTENT_BUILD_FAILED} when intentBuilder throws'
  );

  assert.equal(
    inner_called,
    false,
    'INVARIANT VIOLATION: inner handler ran despite intentBuilder throwing. The adapter must fail closed before the RDP evaluation step.'
  );
});

// ─── Case 6 — intentBuilder returns a non-object ────────────────────────

test('[release-blocker] inner handler does not run when intentBuilder returns a non-object', async () => {
  for (const badReturn of ['not an object', ['array', 'not', 'object'], null, 42]) {
    let inner_called = false;

    const gated = wrapToolHandler(
      async () => {
        inner_called = true;
        return 'ran';
      },
      {
        authz: makeAuthz('allow'),
        toolName: 'write_file',
        intentBuilder: () => badReturn,
      }
    );

    await assert.rejects(
      () => gated({ path: '/tmp/foo' }),
      (err) => err instanceof BlockedByPolicy,
      `wrapped handler must reject when intentBuilder returns ${JSON.stringify(badReturn)}`
    );
    assert.equal(
      inner_called,
      false,
      `INVARIANT VIOLATION: inner handler ran when intentBuilder returned ${JSON.stringify(badReturn)}.`
    );
  }
});

// ─── Case 7 — concurrent gated calls each consult evaluate independently ─

test('[release-blocker] concurrent gated-handler invocations each consult evaluate independently', async () => {
  let evaluate_calls = 0;
  const rdp = {
    async evaluate() {
      const n = ++evaluate_calls;
      await new Promise((r) => setTimeout(r, 30));
      return {
        intentId: `test-intent-${n}`,
        receipt: { token: `v2.fake.sig.${n}` },
        decision: { verdict: 'ALLOW' },
      };
    },
    async close() {},
    async verifyReceipt() { return {}; },
  };

  let inner_count = 0;
  const gated = wrapToolHandler(
    async () => {
      const n = ++inner_count;
      return { ran: n };
    },
    { authz: makeAuthzWithRdp(rdp), toolName: 'write_file', intentBuilder }
  );

  const [r1, r2] = await Promise.all([
    gated({ path: '/tmp/a' }),
    gated({ path: '/tmp/b' }),
  ]);

  assert.equal(evaluate_calls, 2, 'INVARIANT: each gated invocation must call evaluate independently');
  assert.equal(inner_count, 2, 'INVARIANT: each gated invocation must run its own inner handler');
  assert.ok([r1.ran, r2.ran].includes(1) && [r1.ran, r2.ran].includes(2), 'both inner calls completed');
});

// ─── Case 8 — wrapTool wraps a full tool definition and upholds the invariant ─

test('[release-blocker] wrapTool form: inner handler does not run on BLOCK', async () => {
  let inner_called = false;

  const toolDef = {
    name: 'write_file',
    description: 'Write a file.',
    handler: async () => {
      inner_called = true;
      return 'ran';
    },
  };

  const wrapped = wrapTool(toolDef, {
    authz: makeAuthz('deny'),
    intentBuilder,
  });

  await assert.rejects(
    () => wrapped.handler({ path: '/tmp/foo' }),
    (err) => err instanceof BlockedByPolicy
  );
  assert.equal(
    inner_called,
    false,
    'INVARIANT: wrapTool-produced wrapper must enforce Pattern 41 ordering identically to wrapToolHandler.'
  );
  assert.equal(wrapped.name, 'write_file', 'wrapped tool preserves name');
});
