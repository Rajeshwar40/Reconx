'use strict';

/**
 * Validates and sanitizes a domain input.
 * Returns { valid: bool, domain: string, error: string }
 */
function validateDomain(raw) {
  if (!raw || typeof raw !== 'string') {
    return { valid: false, error: 'Domain is required.' };
  }

  // Strip protocol / whitespace
  let domain = raw.trim().toLowerCase();
  domain = domain.replace(/^https?:\/\//i, '');
  domain = domain.replace(/\/.*$/, '');

  // Basic regex: labels separated by dots, no injection chars
  const DOMAIN_RE = /^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/;
  if (!DOMAIN_RE.test(domain)) {
    return { valid: false, error: `Invalid domain format: "${domain}"` };
  }

  // Reject shell meta-characters (extra safety)
  const DANGEROUS = /[;&|`$<>'"\\]/;
  if (DANGEROUS.test(domain)) {
    return { valid: false, error: 'Domain contains illegal characters.' };
  }

  return { valid: true, domain };
}

module.exports = { validateDomain };
