import { createDebug } from 'obug';
import packageJson from '@@/package.json';

import { exec } from '#server/utils/cmd';
import { parseInterfaceName } from '#server/utils/interfaceName';
import {
  parseMaxClientsPerUser,
  parseProxyAdmins,
  parseProxyAuthHeader,
} from '#server/utils/proxyAuth';
import { parseTrustedProxies } from '#server/utils/trustedProxy';
import {
  OAUTH_PROVIDERS,
  isConfiguredOauthProvider,
  isValidOauthProvider,
} from '#server/utils/oauth';

export const RELEASE = 'v' + packageJson.version;

export const SERVER_DEBUG = createDebug('Server');

export const OLD_ENV = {
  /** @deprecated Only for migration purposes */
  PASSWORD: process.env.PASSWORD,
  /** @deprecated Only for migration purposes */
  PASSWORD_HASH: process.env.PASSWORD_HASH,
};

const detectAwg = async (): Promise<'awg' | 'wg'> => {
  /** TODO: delete on next major version */
  if (process.env.EXPERIMENTAL_AWG === 'true') {
    const OVERRIDE_AUTO_AWG = process.env.OVERRIDE_AUTO_AWG?.toLowerCase();

    if (
      OVERRIDE_AUTO_AWG === ('wg' as const) ||
      OVERRIDE_AUTO_AWG === ('awg' as const)
    ) {
      return OVERRIDE_AUTO_AWG;
    } else {
      return await exec('modinfo amneziawg')
        .then(() => 'awg' as const)
        .catch(() => 'wg' as const);
    }
  } else return 'wg';
};

const oauthProviders = process.env.OAUTH_PROVIDERS?.split(',')
  .map((v) => v.trim())
  .filter((v) => isValidOauthProvider(v))
  .filter((v) => isConfiguredOauthProvider(OAUTH_PROVIDERS[v]));

const trustedProxies = parseTrustedProxies(process.env.TRUSTED_PROXIES);
const proxyAuthHeader = parseProxyAuthHeader(
  process.env.PROXY_AUTH_HEADER,
  trustedProxies
);

export const WG_ENV = {
  /** UI is hosted on HTTP instead of HTTPS */
  INSECURE: process.env.INSECURE === 'true',
  /** Port the UI is listening on */
  PORT: assertEnv('PORT'),
  /** If IPv6 should be disabled */
  DISABLE_IPV6: process.env.DISABLE_IPV6 === 'true',
  /** Name of the WireGuard interface */
  WG_INTERFACE: parseInterfaceName(process.env.WG_INTERFACE),
  WG_EXECUTABLE: await detectAwg(),
  DISABLE_VERSION_CHECK: process.env.DISABLE_VERSION_CHECK === 'true',
  /** List of enabled and configured OAuth providers */
  OAUTH_PROVIDERS: oauthProviders,
  /** List of allowed OAuth domains */
  OAUTH_ALLOWED_DOMAINS: process.env.OAUTH_ALLOWED_DOMAINS?.split(',').map(
    (v) => v.trim()
  ),
  /** Automatically register users that log in with an OAuth provider */
  OAUTH_AUTO_REGISTER: process.env.OAUTH_AUTO_REGISTER === 'true',
  /** Which OAuth provider to automatically launch */
  OAUTH_AUTO_LAUNCH:
    oauthProviders?.find((p) => p === process.env.OAUTH_AUTO_LAUNCH) ?? null,
  /**
   * Disable password authentication. Always off with proxy
   * authentication: then the proxy is the only way in
   */
  DISABLE_PASSWORD_AUTH:
    process.env.DISABLE_PASSWORD_AUTH === 'true' ||
    proxyAuthHeader !== undefined,
  /** Proxies allowed to provide forwarded request information */
  TRUSTED_PROXIES: trustedProxies,
  /**
   * Proxy authentication: the (lower-case) request header in which a
   * trusted proxy passes the name of the user it has authenticated
   */
  PROXY_AUTH_HEADER: proxyAuthHeader,
  /** Create an account for a user the proxy vouches for and we do not know */
  PROXY_AUTH_AUTO_REGISTER: process.env.PROXY_AUTH_AUTO_REGISTER === 'true',
  /** User names that are administrators when they come through the proxy */
  PROXY_AUTH_ADMINS: parseProxyAdmins(process.env.PROXY_AUTH_ADMINS),
  /**
   * A file with more administrators' user names, read again whenever it
   * changes
   */
  PROXY_AUTH_ADMINS_FILE:
    process.env.PROXY_AUTH_ADMINS_FILE?.trim() || undefined,
  /** How many clients an ordinary user may have, 0 = no limit */
  MAX_CLIENTS_PER_USER: parseMaxClientsPerUser(
    process.env.MAX_CLIENTS_PER_USER
  ),
  /**
   * The host's firewall and routing belong to somebody else: write no
   * PreUp/PostUp/PreDown/PostDown commands into the interface's
   * configuration, never run iptables, and refuse to change hooks or to
   * switch the per-client firewall on
   */
  DISABLE_HOOKS: process.env.DISABLE_HOOKS === 'true',
};

if (WG_ENV.DISABLE_HOOKS) {
  SERVER_DEBUG(
    'Hooks and per-client firewall: Disabled (DISABLE_HOOKS) - the host firewall is not touched'
  );
}

if (WG_ENV.PROXY_AUTH_HEADER) {
  SERVER_DEBUG(`
Proxy authentication: header ${WG_ENV.PROXY_AUTH_HEADER}, trusted proxies ${WG_ENV.TRUSTED_PROXIES.join(', ')}
Proxy auto register: ${WG_ENV.PROXY_AUTH_AUTO_REGISTER ? 'Enabled' : 'Disabled'}
Proxy administrators: ${WG_ENV.PROXY_AUTH_ADMINS.join(', ') || 'None'}${WG_ENV.PROXY_AUTH_ADMINS_FILE ? ` and those in ${WG_ENV.PROXY_AUTH_ADMINS_FILE}` : ''}
`);
}

if (WG_ENV.OAUTH_PROVIDERS && WG_ENV.OAUTH_PROVIDERS.length > 0) {
  SERVER_DEBUG(`
Enabled OAuth providers: ${WG_ENV.OAUTH_PROVIDERS.join(', ')}
Allowed OAuth domains: ${WG_ENV.OAUTH_ALLOWED_DOMAINS?.join(', ') ?? 'All'}
OAuth auto register: ${WG_ENV.OAUTH_AUTO_REGISTER ? 'Enabled' : 'Disabled'}
Password authentication: ${WG_ENV.DISABLE_PASSWORD_AUTH ? 'Disabled' : 'Enabled'}
Auto launch OAuth provider: ${WG_ENV.OAUTH_AUTO_LAUNCH ?? 'None'}
`);
}

export const WG_INITIAL_ENV = {
  ENABLED: process.env.INIT_ENABLED === 'true',
  USERNAME: process.env.INIT_USERNAME,
  PASSWORD: process.env.INIT_PASSWORD,
  DNS: process.env.INIT_DNS?.split(',').map((x) => x.trim()),
  IPV4_CIDR: process.env.INIT_IPV4_CIDR,
  IPV6_CIDR: process.env.INIT_IPV6_CIDR,
  ALLOWED_IPS: process.env.INIT_ALLOWED_IPS?.split(',').map((x) => x.trim()),
  HOST: process.env.INIT_HOST,
  PORT: process.env.INIT_PORT
    ? Number.parseInt(process.env.INIT_PORT, 10)
    : undefined,
};

function assertEnv<T extends string>(env: T) {
  const val = process.env[env];

  if (!val) {
    throw new Error(`Missing environment variable: ${env}`);
  }

  return val;
}
