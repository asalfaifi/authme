function loginError(code, message) {
  return Object.assign(new Error(message), { code, status: 403, safe: true });
}

export async function resolveFederatedLogin({ realm, result, repository, allowCreate = result?.allowCreate === true }) {
  if (!repository?.resolve) throw new TypeError('A federated identity repository is required');
  const profile = result?.profile;
  const issuer = result?.issuer ?? result?.identity?.issuer;
  const externalSubject = profile?.externalSubject ?? result?.identity?.externalSubject;
  if (!result?.providerId || !issuer || !externalSubject || !profile) {
    throw new TypeError('A validated federation result with provider, issuer, subject, and profile is required');
  }
  const resolution = await repository.resolve({
    realm,
    providerId: result.providerId,
    issuer,
    externalSubject,
    profile,
    allowCreate,
  });
  if (['resolved', 'created'].includes(resolution.status) && resolution.user?.enabled) return resolution;
  if (resolution.status === 'link_required') {
    throw loginError('AUTHME_FEDERATED_LINK_REQUIRED', 'This external identity must be linked by an administrator before it can sign in.');
  }
  if (resolution.status === 'not_found') {
    throw loginError('AUTHME_FEDERATED_ACCOUNT_REQUIRED', 'This external identity is not assigned to an AuthMe account.');
  }
  throw loginError('AUTHME_FEDERATED_LOGIN_DENIED', 'This external identity cannot sign in.');
}
