function validateSender(sender) {
  if (!sender || typeof sender !== 'object'
    || typeof sender.sendEmailVerification !== 'function'
    || typeof sender.sendPasswordReset !== 'function') {
    throw new TypeError('Account email module must provide sendEmailVerification and sendPasswordReset methods');
  }
  return sender;
}

export async function loadAccountEmailSender(config, importer = (specifier) => import(specifier)) {
  if (!config.accountEmailModule) return undefined;
  let loaded;
  try {
    loaded = await importer(config.accountEmailModule);
  } catch (error) {
    throw new Error('Unable to load AUTHME_ACCOUNT_EMAIL_MODULE', { cause: error });
  }
  const exported = loaded.createAccountEmailSender ?? loaded.default;
  const sender = typeof exported === 'function'
    ? await exported(Object.freeze({ publicUrl: config.publicUrl, realms: [...config.realms] }))
    : exported;
  return validateSender(sender);
}
