/** Typed errors raised by the AEAP Composition Boundary Adapter for the Claude Agent SDK. */

export class AiyoClaudeAgentSDKError extends Error {
  constructor(message) {
    super(message);
    this.name = 'AiyoClaudeAgentSDKError';
  }
}

export class AdapterConfigError extends AiyoClaudeAgentSDKError {
  constructor(message) {
    super(message);
    this.name = 'AdapterConfigError';
  }
}

export class BlockedByPolicy extends AiyoClaudeAgentSDKError {
  constructor(message, { reasonCode, intentId, extra } = {}) {
    super(message);
    this.name = 'BlockedByPolicy';
    this.reasonCode = reasonCode;
    this.intentId = intentId;
    this.extra = extra || {};
  }
}

export class EscalationRequired extends AiyoClaudeAgentSDKError {
  constructor(message, { escalationId, intentId, extra } = {}) {
    super(message);
    this.name = 'EscalationRequired';
    this.escalationId = escalationId;
    this.intentId = intentId;
    this.extra = extra || {};
  }
}
