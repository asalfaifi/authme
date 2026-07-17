const primaryMethods = new Set(['password', 'passkey', 'federated']);

function amrSatisfies(type, amr) {
  if (type === 'password') return amr.includes('pwd') || amr.includes('ldap');
  if (type === 'totp') return amr.includes('otp') || amr.includes('recovery');
  if (type === 'passkey') return amr.includes('passkey') || amr.includes('hwk');
  if (type === 'federated') return amr.includes('federated');
  return false;
}

export function authenticationSatisfiesFlow(flow, amr = [], user = {}) {
  if (!flow) return true;
  const methods = Array.isArray(amr) ? amr : [];
  const required = flow.steps.filter((step) => step.requirement === 'required'
    || (step.requirement === 'conditional' && step.type === 'totp' && user?.totpConfirmed));
  if (required.some((step) => !amrSatisfies(step.type, methods))) return false;
  const alternatives = flow.steps.filter((step) => step.requirement === 'alternative');
  return alternatives.length === 0 || alternatives.some((step) => amrSatisfies(step.type, methods));
}

export function totpRequiredForFlow(flow, user = {}) {
  if (!user?.totpConfirmed) return false;
  if (!flow) return true;
  return flow.steps.some((step) => step.type === 'totp'
    && (step.requirement === 'required' || step.requirement === 'conditional'));
}

export function authenticationFlowConfigurationError(steps) {
  if (!Array.isArray(steps) || !steps.length) return 'at least one authentication step is required';
  const seen = new Set();
  for (const step of steps) {
    if (seen.has(step.type)) return `authentication method ${step.type} may only appear once`;
    seen.add(step.type);
    if (step.requirement === 'conditional' && step.type !== 'totp') {
      return 'conditional execution is supported only for TOTP enrollment';
    }
  }
  const requiredPrimary = steps.filter((step) => step.requirement === 'required' && primaryMethods.has(step.type));
  if (requiredPrimary.length > 1) return 'only one primary authentication method can be required';
  const alternatives = steps.filter((step) => step.requirement === 'alternative');
  if (requiredPrimary.length === 0 && alternatives.length === 0) {
    return 'an authentication flow must contain a required or alternative primary method';
  }
  if (alternatives.some((step) => !primaryMethods.has(step.type))) {
    return 'alternative execution is supported only for primary authentication methods';
  }
  if (alternatives.length && steps.some((step) => step.requirement !== 'alternative')) {
    return 'alternative primary methods cannot be combined with required or conditional steps';
  }
  const requiredTotp = steps.some((step) => step.type === 'totp' && step.requirement === 'required');
  if (requiredTotp && requiredPrimary.some((step) => step.type !== 'password')) {
    return 'required TOTP can only be combined with password authentication';
  }
  const conditionalTotp = steps.some((step) => step.type === 'totp' && step.requirement === 'conditional');
  if (conditionalTotp && requiredPrimary.some((step) => step.type !== 'password')) {
    return 'conditional TOTP can only be combined with password authentication';
  }
  return undefined;
}

export function assertAuthenticationFlowConfiguration(steps) {
  const error = authenticationFlowConfigurationError(steps);
  if (error) throw Object.assign(new Error(error), { code: 'AUTH_FLOW_INVALID' });
}
