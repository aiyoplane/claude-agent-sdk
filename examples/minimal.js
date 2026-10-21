/**
 * Minimal example of @aiyoplane/claude-agent-sdk.
 * Simulates a coding-agent surface with a file_write tool.
 *
 * Run: node examples/minimal.js
 *
 * The example demonstrates the full composition pattern against mcp-authz's
 * policy matcher:
 *
 *   1. The adapter-level `intentBuilder` (passed to `wrapToolHandler`)
 *      returns the raw per-call payload the adapter needs. In this example
 *      it carries the raw file path.
 *
 *   2. A top-level `intentBuilder` is passed to `createAiyoMcpAuthz`. It
 *      receives the adapter's intent as `args` and projects it into the
 *      canonical Intent shape mcp-authz's policy matcher consumes
 *      (`action.type` + `action.target` + optional `amount`).
 *
 *   3. The policy rules match on canonical `match.action_type` and
 *      `match.target` fields. mcp-authz's matcher uses strict equality
 *      (no prefix matching, no case folding). Non-canonical rule fields
 *      (`path_prefix`, `action_target`, etc.) are silently ignored.
 *
 * This two-step pattern is the correct composition when adopters want
 * per-call policy discrimination based on fields derived from the raw
 * tool arguments.
 */

import { createAiyoMcpAuthz, createLocalRdp } from '@aiyoplane/mcp-authz';
import {
  BlockedByPolicy,
  EscalationRequired,
  wrapToolHandler,
} from '../src/index.js';

// Classify the raw file path into a canonical target category.
// Pure function; easy to unit-test independently of the authorization flow.
function classifyPathTarget(path) {
  if (typeof path !== 'string') return 'unknown';
  if (path.startsWith('/tmp/')) return 'tmp';
  if (path.startsWith('/etc/')) return 'etc';
  return 'other';
}

const policy = {
  default_effect: 'deny',
  rules: [
    { match: { action_type: 'file_write', target: 'tmp' }, effect: 'allow' },
    { match: { action_type: 'file_write', target: 'etc' }, effect: 'deny' },
    // Catch-all: any file_write that isn't under /tmp/ or /etc/ escalates
    // for human approval. Explicit per-target rules are a safer pattern
    // than a broader allow-by-default.
    { match: { action_type: 'file_write' },                 effect: 'escalate' },
  ],
};

const authz = createAiyoMcpAuthz({
  rdp: createLocalRdp({ policy }),
  toolConfig: {
    write_file: { aiyo_gated: true, action: { type: 'file_write' } },
  },
  // Top-level intentBuilder. Receives the adapter-level intent as `args`
  // (the object the adapter's intentBuilder returned). Projects it into the
  // canonical mcp-authz Intent shape the policy matcher reads.
  //
  // Boundary behavior (verified in test/policy-matching.test.js):
  //   - '/tmp/foo'       → target 'tmp'      → ALLOW
  //   - '/etc/passwd'    → target 'etc'      → DENY  (BlockedByPolicy)
  //   - '/home/user/foo' → target 'other'    → ESCALATE (EscalationRequired)
  //   - '/tmp-evil/foo'  → target 'other'    → ESCALATE (NOT ALLOW; strict equality)
  //   - '/etcetera/foo'  → target 'other'    → ESCALATE (NOT DENY)
  //   - '/TMP/foo'       → target 'other'    → ESCALATE (strict case)
  //   - path missing     → target 'unknown'  → ESCALATE
  intentBuilder: (toolName, args) => ({
    amount: 0,
    currency: 'usd',
    action: { type: 'file_write', target: classifyPathTarget(args.path) },
    metadata: {
      source: 'claude-agent-sdk-example',
      tool_name: toolName,
      path: args.path,
    },
  }),
});

const guardedWriteFile = wrapToolHandler(
  async ({ path, content }) => `Wrote ${content.length} bytes to ${path}`,
  {
    authz,
    toolName: 'write_file',
    intentBuilder: ({ path, content }) => ({
      type: 'file_write',
      path,
      bytes: content?.length ?? 0,
    }),
  }
);

async function main() {
  console.log('ALLOW (/tmp/foo.txt):');
  console.log('  ', await guardedWriteFile({ path: '/tmp/foo.txt', content: 'hello' }));

  console.log('\nESCALATE (/home/user/foo.txt):');
  try {
    await guardedWriteFile({ path: '/home/user/foo.txt', content: 'hello' });
  } catch (err) {
    if (err instanceof EscalationRequired) console.log('  Held:', err.message);
    else throw err;
  }

  console.log('\nDENY (/etc/passwd):');
  try {
    await guardedWriteFile({ path: '/etc/passwd', content: 'evil' });
  } catch (err) {
    if (err instanceof BlockedByPolicy) console.log('  Blocked:', err.message);
    else throw err;
  }
}

main().catch((err) => { console.error(err); process.exit(1); });
