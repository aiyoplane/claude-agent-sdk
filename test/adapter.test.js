import { test } from 'node:test';
import assert from 'node:assert/strict';

import { createAiyoMcpAuthz, createLocalRdp } from '@aiyoplane/mcp-authz';

import {
  AdapterConfigError,
  BlockedByPolicy,
  EscalationRequired,
  wrapTool,
  wrapToolHandler,
} from '../src/index.js';

function makeAuthz(rules) {
  return createAiyoMcpAuthz({
    rdp: createLocalRdp({ policy: { default_effect: 'deny', rules } }),
    toolConfig: { write_file: { aiyo_gated: true, action: { type: 'file_write' } } },
  });
}

test('wrapToolHandler ALLOW runs the handler', async () => {
  const authz = makeAuthz([{ match: { action_type: 'file_write' }, effect: 'allow' }]);
  const gated = wrapToolHandler(
    async ({ path, content }) => `Wrote ${content.length} bytes to ${path}`,
    { authz, toolName: 'write_file', intentBuilder: ({ path }) => ({ type: 'file_write', path }) }
  );
  const result = await gated({ path: '/tmp/foo', content: 'hi' });
  assert.match(result, /Wrote 2/);
});

test('wrapToolHandler BLOCK prevents execution', async () => {
  const authz = makeAuthz([{ match: { action_type: 'file_write' }, effect: 'deny' }]);
  const gated = wrapToolHandler(
    async () => 'should not run',
    { authz, toolName: 'write_file', intentBuilder: () => ({ type: 'file_write' }) }
  );
  await assert.rejects(
    gated({ path: '/etc/passwd', content: 'evil' }),
    (err) => err instanceof BlockedByPolicy
  );
});

test('wrapToolHandler ESCALATE raises', async () => {
  const authz = makeAuthz([{ match: { action_type: 'file_write' }, effect: 'escalate' }]);
  const gated = wrapToolHandler(
    async () => 'should not run',
    { authz, toolName: 'write_file', intentBuilder: () => ({ type: 'file_write' }) }
  );
  await assert.rejects(
    gated({ path: '/home/user/foo', content: 'hi' }),
    (err) => err instanceof EscalationRequired || err instanceof BlockedByPolicy
  );
});

test('wrapToolHandler broken intentBuilder blocks', async () => {
  const authz = makeAuthz([{ match: { action_type: 'file_write' }, effect: 'allow' }]);
  const gated = wrapToolHandler(
    async () => 'ok',
    {
      authz,
      toolName: 'write_file',
      intentBuilder: () => { throw new Error('broken'); },
    }
  );
  await assert.rejects(
    gated({ path: '/tmp/foo', content: 'hi' }),
    (err) => err instanceof BlockedByPolicy
  );
});

test('wrapToolHandler non-object intent blocks', async () => {
  const authz = makeAuthz([{ match: { action_type: 'file_write' }, effect: 'allow' }]);
  const gated = wrapToolHandler(
    async () => 'ok',
    { authz, toolName: 'write_file', intentBuilder: () => 'not an object' }
  );
  await assert.rejects(
    gated({ path: '/tmp/foo', content: 'hi' }),
    (err) => err instanceof BlockedByPolicy
  );
});

test('wrapToolHandler non-function raises AdapterConfigError', () => {
  const authz = makeAuthz([{ match: { action_type: 'file_write' }, effect: 'allow' }]);
  assert.throws(
    () => wrapToolHandler('not a fn', {
      authz, toolName: 'write_file', intentBuilder: () => ({ type: 'file_write' }),
    }),
    (err) => err instanceof AdapterConfigError
  );
});

test('wrapTool wraps full tool definition', async () => {
  const authz = makeAuthz([{ match: { action_type: 'file_write' }, effect: 'allow' }]);
  const toolDef = {
    name: 'write_file',
    description: 'Write a file.',
    handler: async ({ path, content }) => `Wrote ${content.length} bytes to ${path}`,
  };
  const gated = wrapTool(toolDef, {
    authz,
    intentBuilder: ({ path }) => ({ type: 'file_write', path }),
  });
  const result = await gated.handler({ path: '/tmp/foo', content: 'hi' });
  assert.match(result, /Wrote 2/);
  assert.equal(gated.name, 'write_file');
});
