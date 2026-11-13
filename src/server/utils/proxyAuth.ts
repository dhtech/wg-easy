import { getHeader, type H3Event } from 'h3';

import { isRequestFromTrustedProxy } from '#server/utils/trustedProxy';

/**
 * Proxy authentication: a reverse proxy in front of wg-easy has already
 * asked who is there (basic auth against a directory, a single sign-on
 * portal, ...) and passes the user name on in a request header.
 *
 * The header is believed ONLY when the request comes from one of the
 * TRUSTED_PROXIES. From anybody else it is ignored: everyone can write
 * a header.
 */

/** user names a proxy may hand over: what directories use, nothing exotic */
const PROXY_USERNAME = /^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$/;

export type ProxyAuthConfig = {
  /** lower-case name of the header, undefined = proxy authentication off */
  header: string | undefined;
  trustedProxies: readonly string[];
};

/**
 * Name of the header that carries the user name, as given in
 * `PROXY_AUTH_HEADER`. Proxy authentication without trusted proxies would
 * let every client name itself, so that combination is refused.
 *
 * @throws
 */
export function parseProxyAuthHeader(
  value: string | undefined,
  trustedProxies: readonly string[]
): string | undefined {
  const header = value?.trim().toLowerCase();
  if (!header) {
    return undefined;
  }
  if (!/^[a-z0-9-]+$/.test(header)) {
    throw new Error(`Invalid PROXY_AUTH_HEADER: ${value}`);
  }
  if (trustedProxies.length === 0) {
    throw new Error(
      'PROXY_AUTH_HEADER needs TRUSTED_PROXIES: without it the header would be believed from anybody'
    );
  }
  return header;
}

/**
 * A user name as a proxy may hand it over, or `undefined` if the value
 * is missing or not a plain user name.
 */
export function parseProxyUsername(
  value: string | undefined
): string | undefined {
  // directories do not tell upper and lower case apart in a login name:
  // "Alice" and "alice" must be the same account here too
  const username = value?.trim().toLowerCase();
  if (!username || !PROXY_USERNAME.test(username)) {
    return undefined;
  }
  return username;
}

/**
 * The user names of `PROXY_AUTH_ADMINS` (comma separated). Everybody else
 * who comes through the proxy is an ordinary user and sees only their
 * own clients.
 *
 * @throws
 */
export function parseProxyAdmins(value: string | undefined): string[] {
  if (!value) {
    return [];
  }
  return value
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map((entry) => {
      const username = parseProxyUsername(entry);
      if (!username) {
        throw new Error(`Invalid user name in PROXY_AUTH_ADMINS: ${entry}`);
      }
      return username;
    });
}

/**
 * `MAX_CLIENTS_PER_USER`: how many clients an ordinary user may have.
 * 0 (the default) means no limit.
 *
 * @throws
 */
export function parseMaxClientsPerUser(value: string | undefined): number {
  if (value === undefined || value.trim() === '') {
    return 0;
  }
  if (!/^\d+$/.test(value.trim())) {
    throw new Error(`Invalid MAX_CLIENTS_PER_USER: ${value}`);
  }
  return Number.parseInt(value.trim(), 10);
}

/**
 * The user name the trusted proxy vouches for on this request.
 * `undefined` when proxy authentication is off, when the request did not
 * come through a trusted proxy, or when the header is absent or unusable.
 */
export function getProxyAuthUsername(
  event: H3Event,
  config: ProxyAuthConfig
): string | undefined {
  if (!config.header) {
    return undefined;
  }
  if (!isRequestFromTrustedProxy(event, config.trustedProxies)) {
    return undefined;
  }
  return parseProxyUsername(getHeader(event, config.header));
}
