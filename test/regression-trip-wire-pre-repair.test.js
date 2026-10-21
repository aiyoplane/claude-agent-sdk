// NEGATIVE-CONTROL test for the pre-1.0.1 broken example configuration.
//
// PURPOSE
// -------
// This file documents the historical failure mode of the example shipped in
// the GitHub repository before 1.0.1. It is NOT a specification of desired
// current behavior. Reading this test as "we want the handler to run on
// /etc/passwd" is a misreading — the test asserts the handler DID run under
// the historical broken config, which is precisely why that config was unsafe.
//
// A reader modifying this test should ask: "am I preserving the documentation
// of an historical defect, or am I changing current behavior?" If current
// behavior, you are in the wrong file; the current-behavior conformance tests
// live in test/policy-matching.test.js (ALLOW/DENY/ESCALATE for the repaired
// configuration) and test/pattern-41-ordering.test.js (Pattern 41 ordering
// invariant).
//
// SAFETY CLAIM
// ------------
// The handler used throughout this file is a PURE MOCK. It:
//   - sets a boolean flag on an in-memory object
//   - records the arguments it was called with on an in-memory object
//   - returns a FORMATTED STRING describing what a real handler WOULD have done
//
// It does NOT:
//   - call fs.writeFile, fs.writeFileSync, fs.open, or any filesystem API
//   - call child_process.*, exec*, spawn*, or any subprocess API
//   - make network calls (no fetch, http, https, net, dgram)
//   - import or require any of the above modules
//
// If a future contributor adds a real filesystem write to this file, that is
// a defect — the trip-wire's value is as a BEHAVIORAL claim about the gate,
// not as a demonstration of what a real handler does.
//
// DEPENDENCY ASSUMPTIONS
// ----------------------
// This test depends on the following observable behavior of @aiyoplane/mcp-authz
// at version 1.1.0:
//
//   - mcp-authz reads `toolDef.aiyo_gated` (snake_case). The camelCase form
//     `aiyoGated` is NOT read and therefore evaluates to falsy, which causes
//     mcp-authz to treat the tool as UNGATED (the RDP is not consulted).
//
// If a future mcp-authz version adds camelCase support, or otherwise changes
// how the gating flag is read, this test will stop asserting what it currently
// documents. In that case the correct action is NOT to "fix" this test; the
// correct action is to re-audit cross-adapter example configurations and
// update this negative-control's assumptions, OR delete this test if the
// historical failure mode is no longer reachable.
//
// Pinning: package.json pins @aiyoplane/mcp-authz: ^1.0.0. The behavior
// documented here was observed against 1.1.0. If adopters install a later
// major version that behaves differently, this test's job is to fail loudly
// so the discrepancy is caught before shipping.
//
// Run: node --test test/regression-trip-wire-pre-repair.test.js

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { createAiyoMcpAuthz, createLocalRdp } from '@aiyoplane/mcp-authz';

import { wrapToolHandler } from '../src/index.js';

// Pure mock handler. See SAFETY CLAIM above.
function makeMockHandler() {
  const log = { invoked: false, received: null, calls: 0 };
  const handler = async ({ path, content }) => {
    log.invoked = true;
    log.received = { path, content };
    log.calls += 1;
    return `[MOCK; NOT A REAL WRITE] handler was invoked with path=${path}, content.length=${content?.length ?? 0}`;
  };
  return { handler, log };
}

// The pre-1.0.1 broken example configuration, reproduced verbatim.
// - toolConfig uses `aiyoGated` (camelCase) instead of `aiyo_gated` (snake_case).
// - rule uses top-level `action_type` instead of `match.action_type`.
// - rule uses non-canonical `path_prefix` and `effect: 'block'`.
//
// Expected observable consequence under mcp-authz 1.1.0:
//   `aiyoGated` is not read → `toolDef.aiyo_gated` is undefined → mcp-authz
//   treats the tool as ungated → the RDP is bypassed → the handler runs
//   on every call, including paths the author intended to prohibit.
const PRE_REPAIR_BROKEN_POLICY = {
  default_effect: 'deny',
  rules: [
    { action_type: 'file_write', path_prefix: '/tmp/',  effect: 'allow'    },
    { action_type: 'file_write', path_prefix: '/etc/',  effect: 'block'    },
    { action_type: 'file_write',                        effect: 'escalate' },
  ],
};

function makePreRepairBrokenAuthz() {
  return createAiyoMcpAuthz({
    rdp: createLocalRdp({ policy: PRE_REPAIR_BROKEN_POLICY }),
    toolConfig: {
      // DELIBERATELY camelCase. This is the historical defect.
      write_file: { aiyoGated: true, action: { type: 'file_write' } },
    },
    // No top-level intentBuilder — matches the pre-repair state.
  });
}

// ─── Historical failure mode: /etc/passwd is reachable under the broken config ─

test('[negative-control] pre-1.0.1 broken config: /etc/passwd write reaches the mock handler', async () => {
  const authz = makePreRepairBrokenAuthz();
  const { handler, log } = makeMockHandler();

  const gated = wrapToolHandler(handler, {
    authz,
    toolName: 'write_file',
    intentBuilder: ({ path, content }) => ({ type: 'file_write', path, bytes: content?.length ?? 0 }),
  });

  // Historical observation: under the broken config, the handler runs.
  // We assert the historical observation. If this stops being observable,
  // see "DEPENDENCY ASSUMPTIONS" in the file header.
  const result = await gated({ path: '/etc/passwd', content: 'malicious' });

  assert.equal(
    log.invoked,
    true,
    'NEGATIVE CONTROL: under the pre-1.0.1 camelCase aiyoGated config, mcp-authz did not read the gating flag and the handler was invoked. If this flipped to false, mcp-authz has changed its gating-flag read behavior; re-audit before updating.'
  );
  assert.equal(log.calls, 1, 'handler ran exactly once; no retry');
  assert.deepEqual(
    log.received,
    { path: '/etc/passwd', content: 'malicious' },
    'handler received the raw args; the gate was bypassed'
  );
  assert.match(
    result,
    /\[MOCK; NOT A REAL WRITE\]/,
    'SAFETY: the handler return value explicitly identifies itself as a mock; no actual filesystem write occurred'
  );
});

test('[negative-control] pre-1.0.1 broken config: /home/user path also reaches the handler (not escalated)', async () => {
  const authz = makePreRepairBrokenAuthz();
  const { handler, log } = makeMockHandler();

  const gated = wrapToolHandler(handler, {
    authz,
    toolName: 'write_file',
    intentBuilder: ({ path, content }) => ({ type: 'file_write', path, bytes: content?.length ?? 0 }),
  });

  const result = await gated({ path: '/home/user/foo', content: 'x' });

  assert.equal(
    log.invoked,
    true,
    'NEGATIVE CONTROL: the broken config did not escalate; the handler ran. This is the failure mode the 1.0.1 repair closes.'
  );
  assert.match(result, /\[MOCK; NOT A REAL WRITE\]/);
});

// ─── Contrast assertion: the REPAIRED config does the right thing ────────────
//
// This test re-asserts current-behavior correctness here (not just in
// policy-matching.test.js) so that a reader of this negative-control file
// can see the delta without jumping between files. It is a thin check; the
// authoritative current-behavior conformance remains in policy-matching.test.js.

test('[contrast] repaired config: /etc/passwd write is rejected and the handler does NOT run', async () => {
  const REPAIRED_POLICY = {
    default_effect: 'deny',
    rules: [
      { match: { action_type: 'file_write', target: 'tmp' }, effect: 'allow' },
      { match: { action_type: 'file_write', target: 'etc' }, effect: 'deny' },
      { match: { action_type: 'file_write' },                 effect: 'escalate' },
    ],
  };

  function classifyPathTarget(path) {
    if (typeof path !== 'string') return 'unknown';
    if (path.startsWith('/tmp/')) return 'tmp';
    if (path.startsWith('/etc/')) return 'etc';
    return 'other';
  }

  const repairedAuthz = createAiyoMcpAuthz({
    rdp: createLocalRdp({ policy: REPAIRED_POLICY }),
    toolConfig: {
      write_file: { aiyo_gated: true, action: { type: 'file_write' } },
    },
    intentBuilder: (toolName, args) => ({
      amount: 0,
      currency: 'usd',
      action: { type: 'file_write', target: classifyPathTarget(args.path) },
      metadata: { source: 'contrast-check', tool_name: toolName, path: args.path },
    }),
  });

  const { handler, log } = makeMockHandler();
  const gated = wrapToolHandler(handler, {
    authz: repairedAuthz,
    toolName: 'write_file',
    intentBuilder: ({ path, content }) => ({ type: 'file_write', path, bytes: content?.length ?? 0 }),
  });

  await assert.rejects(
    gated({ path: '/etc/passwd', content: 'malicious' }),
    (err) => err && (err.name === 'BlockedByPolicy' || err.name === 'EscalationRequired'),
    'repaired config must reject /etc/passwd'
  );

  assert.equal(
    log.invoked,
    false,
    'RELEASE GUARD: under the repaired config, the handler MUST NOT run for /etc/passwd. If this flips to true, the repair has regressed and the trip-wire has failed its job.'
  );
});
