/**
 * @aiyoplane/claude-agent-sdk (Node)
 *
 * AEAP Composition Boundary Adapter for the Claude Agent SDK.
 *
 * Wraps a tool handler so the AEAP Runtime Decision Point evaluates an
 * Intent before the handler runs. Especially useful for coding-agent
 * surfaces (file write, command execution, dependency install, git push,
 * deploy) where consequential execution happens on the client side.
 *
 * Aiyoplane, Inc. — Apache 2.0 licensed.
 * https://aiyoplane.com
 *
 * Specification: https://github.com/aiyoplane/aeap
 */

import {
  AdapterConfigError,
  AiyoClaudeAgentSDKError,
  BlockedByPolicy,
  EscalationRequired,
} from './errors.js';

export { AdapterConfigError, AiyoClaudeAgentSDKError, BlockedByPolicy, EscalationRequired };

/**
 * Wrap a Claude Agent SDK tool handler with an AEAP Composition Boundary.
 *
 * @param {function} handler - The underlying tool handler
 * @param {object} options
 * @param {object} options.authz - AiyoAuthz from @aiyoplane/mcp-authz
 * @param {string} options.toolName - Key in authz.toolConfig for this tool
 * @param {function} options.intentBuilder - (toolArgs) => Intent payload (object)
 * @param {boolean} [options.returnReceipt=false] - If true, result on ALLOW is {result, aeapReceipt}
 * @returns {function} The wrapped handler
 */
export function wrapToolHandler(handler, { authz, toolName, intentBuilder, returnReceipt = false } = {}) {
  if (typeof handler !== 'function') {
    throw new AdapterConfigError(`wrapToolHandler expected a function, got ${typeof handler}`);
  }
  if (typeof intentBuilder !== 'function') {
    throw new AdapterConfigError('wrapToolHandler requires an intentBuilder function');
  }
  if (typeof toolName !== 'string' || !toolName) {
    throw new AdapterConfigError('wrapToolHandler requires a non-empty toolName');
  }

  return async function gatedHandler(toolArgs) {
    const args = toolArgs || {};
    const intent = _buildIntent(intentBuilder, args, toolName);
    const ctx = await _evaluateRdp(authz, toolName, intent);
    const result = await handler(args);
    if (returnReceipt) {
      return { result, aeapReceipt: ctx?.receipt ?? null };
    }
    return result;
  };
}

/**
 * Wrap a full Claude Agent SDK tool definition. Expects an object with at
 * least `name` and `handler`; returns a new tool definition with the gated
 * handler.
 */
export function wrapTool(toolDef, { authz, intentBuilder, toolNameForAuthz, returnReceipt = false } = {}) {
  if (!toolDef || typeof toolDef.name !== 'string') {
    throw new AdapterConfigError('wrapTool expected a Claude Agent SDK tool definition');
  }
  const handler = toolDef.handler;
  if (typeof handler !== 'function') {
    throw new AdapterConfigError('wrapTool expected tool.handler to be a function');
  }
  const resolvedName = toolNameForAuthz || toolDef.name;
  return {
    ...toolDef,
    handler: wrapToolHandler(handler, {
      authz,
      toolName: resolvedName,
      intentBuilder,
      returnReceipt,
    }),
  };
}

// --- Internals -------------------------------------------------------------

function _buildIntent(builder, args, toolName) {
  let intent;
  try {
    intent = builder(args);
  } catch (err) {
    throw new BlockedByPolicy(
      `intentBuilder for tool '${toolName}' raised: ${err?.message || err}`,
      { reasonCode: 'INTENT_BUILD_FAILED' }
    );
  }
  if (!intent || typeof intent !== 'object' || Array.isArray(intent)) {
    throw new BlockedByPolicy(
      `intentBuilder for tool '${toolName}' did not return a plain object`,
      { reasonCode: 'INTENT_SHAPE_INVALID' }
    );
  }
  return intent;
}

async function _evaluateRdp(authz, toolName, intent) {
  if (!authz || typeof authz.wrap !== 'function') {
    throw new AdapterConfigError('invalid authz (missing .wrap)');
  }
  let wrapped;
  try {
    wrapped = authz.wrap(toolName, async (_args, ctx) => ctx);
  } catch (err) {
    throw new BlockedByPolicy(
      `authz.wrap('${toolName}') failed: ${err?.message || err}`,
      { reasonCode: err?.name || 'AUTHZ_WRAP_FAILED' }
    );
  }
  try {
    return await wrapped(intent, null);
  } catch (err) {
    const msg = err?.message || String(err);
    if (/escalat/i.test(msg) || /ESCALATE/.test(msg)) {
      throw new EscalationRequired(
        `AEAP ESCALATE verdict for tool '${toolName}' (intent=${JSON.stringify(intent)}): ${msg}`,
        { extra: { innerException: err?.name, intent } }
      );
    }
    throw new BlockedByPolicy(
      `AEAP non-ALLOW verdict for tool '${toolName}' (intent=${JSON.stringify(intent)}): ${msg}`,
      { reasonCode: err?.name || 'RDP_NON_ALLOW', extra: { innerException: err?.name, intent } }
    );
  }
}
