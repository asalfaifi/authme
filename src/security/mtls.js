import { X509Certificate } from 'node:crypto';
import { BlockList, isIP } from 'node:net';
import {
  Name,
  SubjectAlternativeNameExtension,
  X509Certificate as ParsedX509Certificate,
} from '@peculiar/x509';

const maxCertificateHeaderLength = 16_384;

function singleHeaderValue(ctx, name) {
  const rawHeaders = ctx.req?.rawHeaders;
  if (!Array.isArray(rawHeaders)) return undefined;
  let value;
  let count = 0;
  for (let index = 0; index < rawHeaders.length; index += 2) {
    if (rawHeaders[index].toLowerCase() === name) {
      count += 1;
      value = rawHeaders[index + 1];
    }
  }
  return count === 1 && typeof value === 'string' ? value : undefined;
}

function normalizedRemoteAddress(value) {
  if (value?.startsWith('::ffff:') && isIP(value.slice(7)) === 4) return value.slice(7);
  return value;
}

function trustedProxyList(cidrs) {
  const list = new BlockList();
  for (const { address, family, prefix } of cidrs) {
    const type = family === 4 ? 'ipv4' : 'ipv6';
    if (prefix === undefined) list.addAddress(address, type);
    else list.addSubnet(address, prefix, type);
  }
  return list;
}

function trustedProxyRequest(ctx, proxyList) {
  const remoteAddress = normalizedRemoteAddress(ctx.req?.socket?.remoteAddress);
  const family = isIP(remoteAddress);
  if (!family || !proxyList.check(remoteAddress, family === 4 ? 'ipv4' : 'ipv6')) return false;

  const forwardedFor = singleHeaderValue(ctx, 'x-forwarded-for')?.trim();
  return Boolean(forwardedFor && !forwardedFor.includes(',') && isIP(forwardedFor));
}

function decodeCertificate(value) {
  if (value.length > maxCertificateHeaderLength || value.includes('\0')) return undefined;
  let pem = value;
  try {
    if (pem.includes('%')) pem = decodeURIComponent(pem);
  } catch {
    return undefined;
  }
  pem = pem.trim();
  if (pem.length > maxCertificateHeaderLength
    || !pem.startsWith('-----BEGIN CERTIFICATE-----')
    || !pem.endsWith('-----END CERTIFICATE-----')
    || pem.indexOf('-----BEGIN CERTIFICATE-----', 1) !== -1) {
    return undefined;
  }
  try {
    const certificate = new X509Certificate(pem);
    const now = Date.now();
    if (now < certificate.validFromDate.getTime() || now >= certificate.validToDate.getTime()) return undefined;
    return certificate;
  } catch {
    return undefined;
  }
}

function normalizedDn(name) {
  const rdns = name.toJSON().map((rdn) => Object.fromEntries(
    Object.entries(rdn)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([type, values]) => [type, [...values]]),
  ));
  return JSON.stringify(rdns);
}

function dnMatches(certificate, expected) {
  try {
    const actual = certificate.subjectName.toJSON();
    const wanted = normalizedDn(new Name(expected));
    return normalizedDn(certificate.subjectName) === wanted
      || normalizedDn(new Name([...actual].reverse())) === wanted;
  } catch {
    return false;
  }
}

function sanMatches(certificate, property, expected) {
  const type = {
    tls_client_auth_san_dns: 'dns',
    tls_client_auth_san_email: 'email',
    tls_client_auth_san_ip: 'ip',
    tls_client_auth_san_uri: 'url',
  }[property];
  if (!type) return false;
  const extension = certificate.getExtension(SubjectAlternativeNameExtension);
  const values = extension?.names.items.filter((name) => name.type === type).map((name) => name.value) ?? [];
  if (type === 'dns') return values.some((value) => value.toLowerCase() === expected.toLowerCase());
  if (type === 'ip') {
    const expectedFamily = isIP(expected);
    return Boolean(expectedFamily && values.some((value) => {
      const normalized = normalizedRemoteAddress(value);
      return isIP(normalized) === expectedFamily && normalized === normalizedRemoteAddress(expected);
    }));
  }
  return values.includes(expected);
}

export function createMtlsFeatureConfiguration(config) {
  if (!config.mtls.enabled) return { enabled: false };
  const proxyList = trustedProxyList(config.mtls.trustedProxyCidrs);
  const certificateCache = new WeakMap();
  const parsedCertificateCache = new WeakMap();

  function getCertificate(ctx) {
    if (certificateCache.has(ctx)) return certificateCache.get(ctx) ?? undefined;
    let certificate;
    if (trustedProxyRequest(ctx, proxyList)) {
      const value = singleHeaderValue(ctx, config.mtls.clientCertHeader);
      if (value !== undefined) certificate = decodeCertificate(value);
    }
    certificateCache.set(ctx, certificate ?? null);
    return certificate;
  }

  function parsedCertificate(ctx) {
    const certificate = getCertificate(ctx);
    if (!certificate) return undefined;
    if (!parsedCertificateCache.has(certificate)) {
      try {
        parsedCertificateCache.set(certificate, new ParsedX509Certificate(certificate.raw));
      } catch {
        parsedCertificateCache.set(certificate, null);
      }
    }
    return parsedCertificateCache.get(certificate) ?? undefined;
  }

  return {
    enabled: true,
    certificateBoundAccessTokens: true,
    selfSignedTlsClientAuth: true,
    tlsClientAuth: true,
    getCertificate,
    certificateAuthorized(ctx) {
      return Boolean(getCertificate(ctx)
        && singleHeaderValue(ctx, config.mtls.clientCertVerifiedHeader)
          === config.mtls.clientCertVerifiedValue);
    },
    certificateSubjectMatches(ctx, property, expected) {
      if (typeof expected !== 'string') return false;
      const certificate = parsedCertificate(ctx);
      if (!certificate) return false;
      if (property === 'tls_client_auth_subject_dn') return dnMatches(certificate, expected);
      return sanMatches(certificate, property, expected);
    },
  };
}
