/**
 * Minimal example of @aiyoplane/claude-agent-sdk.
 * Simulates a coding-agent surface with a file_write tool.
 *
 * Run: node examples/minimal.js
 */

import { createAiyoMcpAuthz, createLocalRdp } from '@aiyoplane/mcp-authz';
import {
  BlockedByPolicy,
  EscalationRequired,
  wrapToolHandler,
} from '../src/index.js';

const policy = {
  rules: [
    { action_type: 'file_write', path_prefix: '/tmp/', effect: 'allow' },
    { action_type: 'file_write', path_prefix: '/etc/', effect: 'block' },
    { action_type: 'file_write', effect: 'escalate' },
  ],
};

const authz = createAiyoMcpAuthz({
  rdp: createLocalRdp({ policy }),
  toolConfig: {
    write_file: { aiyoGated: true, action: { type: 'file_write' } },
  },
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
  console.log('ALLOW (/tmp/foo):');
  console.log('  ', await guardedWriteFile({ path: '/tmp/foo.txt', content: 'hello' }));

  console.log('\nESCALATE (/home/user/foo):');
  try {
    await guardedWriteFile({ path: '/home/user/foo.txt', content: 'hello' });
  } catch (err) {
    if (err instanceof EscalationRequired) console.log('  Held:', err.message);
    else throw err;
  }

  console.log('\nBLOCK (/etc/passwd):');
  try {
    await guardedWriteFile({ path: '/etc/passwd', content: 'evil' });
  } catch (err) {
    if (err instanceof BlockedByPolicy) console.log('  Blocked:', err.message);
    else throw err;
  }
}

main().catch((err) => { console.error(err); process.exit(1); });
