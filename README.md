# @aiyoplane/claude-agent-sdk

**AEAP Composition Boundary Adapter for the Claude Agent SDK (Node).**

A thin wrapper that attaches the AEAP Runtime Decision Point (RDP) to the Claude Agent SDK's tool-invocation surface. Consequential tool executions — file writes, command execution, dependency installs, git pushes, deployments — produce independently verifiable Execution Receipts.

```bash
npm install @aiyoplane/claude-agent-sdk
```

## Why coding-agent surfaces specifically

Coding agents produce some of the clearest consequential execution boundaries imaginable:

```
read file  →  modify file  →  run command  →  install dependency  →  git push  →  deploy  →  production
```

Each arrow crosses a Composition Boundary. The question *"may this agent perform this class of action?"* is handled by identity, delegation, and runtime permissions. *"Should this specific file write / this specific command / this specific deploy execute right now, under the Protected Party's current Policy?"* is AEAP's territory.

**Positioning:** Claude can decide what it wants to do. AEAP provides an independently verifiable authorization decision at the point where consequential execution occurs.

See the [AEAP specification](https://github.com/aiyoplane/aeap) §9.

## Minimal usage

```javascript
import { createAiyoMcpAuthz, createLocalRdp } from '@aiyoplane/mcp-authz';
import { wrapToolHandler, BlockedByPolicy, EscalationRequired } from '@aiyoplane/claude-agent-sdk';

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
  async ({ path, content }) => {
    await fs.writeFile(path, content);
    return `Wrote ${content.length} bytes to ${path}`;
  },
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

// Register with your Claude Agent SDK agent the usual way.
```

## Wrapping a full tool definition

```javascript
import { wrapTool } from '@aiyoplane/claude-agent-sdk';

const writeTool = {
  name: 'write_file',
  description: 'Write content to a file.',
  input_schema: { /* ... */ },
  handler: async ({ path, content }) => {
    await fs.writeFile(path, content);
    return `Wrote ${content.length} bytes to ${path}`;
  },
};

const guardedWriteTool = wrapTool(writeTool, {
  authz,
  intentBuilder: ({ path }) => ({ type: 'file_write', path }),
});
```

## Composition Boundary — what the adapter actually does

1. **Intent construction** via `intentBuilder(toolArgs)`.
2. **RDP evaluation** via `@aiyoplane/mcp-authz`.
3. **Verdict composition.** ALLOW → inner handler runs; ESCALATE → `EscalationRequired`; BLOCK → `BlockedByPolicy`.
4. **Fail-closed default** on every ambiguous condition.

## Local vs. hosted RDP

```javascript
// Development:
const authz = createAiyoMcpAuthz({ rdp: createLocalRdp({ policy }), toolConfig });

// Production:
const authz = createAiyoMcpAuthz({
  rdp: createHostedRdp({ apiKey: 'aiyo_live_...' }),
  toolConfig,
});
```

## API reference

### `wrapToolHandler(handler, { authz, toolName, intentBuilder, returnReceipt })`
Wrap a bare handler function.

### `wrapTool(toolDef, { authz, intentBuilder, toolNameForAuthz, returnReceipt })`
Wrap a full tool definition.

### Exceptions

- `AiyoClaudeAgentSDKError`, `AdapterConfigError`, `BlockedByPolicy`, `EscalationRequired`

## License

Apache License 2.0.

## Links

- **AEAP specification:** https://github.com/aiyoplane/aeap
- **Underlying implementation:** [`@aiyoplane/mcp-authz`](https://www.npmjs.com/package/@aiyoplane/mcp-authz)
- **Python sibling:** `aiyoplane-claude-agent-sdk` on PyPI
- **Trust surface:** https://aiyoplane.com/trust
- **Issues:** https://github.com/aiyoplane/claude-agent-sdk/issues

Claude and the Claude Agent SDK are trademarks of Anthropic, PBC. This package is an independent AEAP Composition Boundary Adapter and is not affiliated with or endorsed by Anthropic, PBC.

**Verify First. Execute Second.**
