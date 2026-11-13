import { createError, getHeader, getSession, useSession } from 'h3';
import type { H3Event } from 'h3';

import Database from '#server/utils/Database';
import { WG_ENV } from '#server/utils/config';
import { isPasswordValid } from '#server/utils/password';
import { getProxyAuthUsername } from '#server/utils/proxyAuth';
import type { ID } from '#server/utils/types';
import { roles } from '#shared/utils/permissions';
import type { UserType } from '#db/repositories/user/types';

export type WGSession = Partial<{
  userId: ID;
  pendingLogin: {
    type: 'password' | 'oauth';
    userId: ID;
    remember: boolean;
    /** in milliseconds */
    expires_at: number;
  };
  oauth_verifier: string;
  oauth_nonce: string;
  oauth_state: string;
}>;

const name = 'wg-easy';

export async function useWGSession(event: H3Event, rememberMe = false) {
  const sessionConfig = await Database.general.getSessionConfig();
  return useSession<WGSession>(event, {
    password: sessionConfig.sessionPassword,
    name,
    // TODO: add session expiration
    // maxAge: undefined
    cookie: {
      maxAge: rememberMe ? sessionConfig.sessionTimeout : undefined,
      secure: !WG_ENV.INSECURE,
    },
  });
}

export async function getWGSession(event: H3Event) {
  const sessionConfig = await Database.general.getSessionConfig();
  return getSession<WGSession>(event, {
    password: sessionConfig.sessionPassword,
    name,
    cookie: {
      secure: !WG_ENV.INSECURE,
    },
  });
}

/**
 * Proxy authentication: the account of the user the trusted reverse
 * proxy has authenticated for this request, if any.
 */
async function getProxyUser(event: H3Event) {
  const username = getProxyAuthUsername(event, {
    header: WG_ENV.PROXY_AUTH_HEADER,
    trustedProxies: WG_ENV.TRUSTED_PROXIES,
  });
  if (!username) {
    return undefined;
  }
  const role = WG_ENV.PROXY_AUTH_ADMINS.includes(username)
    ? roles.ADMIN
    : roles.CLIENT;
  return Database.users.getForProxy(
    username,
    role,
    WG_ENV.PROXY_AUTH_AUTO_REGISTER
  );
}

/**
 * @throws
 */
export async function getCurrentUser(event: H3Event) {
  if (WG_ENV.PROXY_AUTH_HEADER) {
    // the proxy is the only way in: no session, no password, no header
    // from anybody but the proxy
    const proxyUser = await getProxyUser(event);
    if (!proxyUser) {
      throw createError({
        statusCode: 401,
        statusMessage: 'Session failed. Not authenticated by the proxy',
      });
    }
    if (!proxyUser.enabled) {
      throw createError({
        statusCode: 403,
        statusMessage: 'User is disabled',
      });
    }
    return proxyUser;
  }

  const session = await getWGSession(event);

  const authorization = getHeader(event, 'Authorization');

  let user: UserType | undefined;
  if (session.data.userId) {
    // Handle if authenticating using Session
    user = await Database.users.get(session.data.userId);
  } else if (authorization) {
    if (WG_ENV.DISABLE_PASSWORD_AUTH) {
      throw createError({
        statusCode: 403,
        statusMessage: 'Password authentication is disabled',
      });
    }

    // Handle if authenticating using Header
    const [method, value] = authorization.split(' ');
    // Support Basic Authentication
    // TODO: support personal access token or similar
    if (method !== 'Basic' || !value) {
      throw createError({
        statusCode: 400,
        statusMessage: 'Invalid Basic Authorization',
      });
    }

    const basicValue = Buffer.from(value, 'base64').toString('utf-8');

    // Split by first ":"
    const index = basicValue.indexOf(':');
    const username = basicValue.substring(0, index);
    const password = basicValue.substring(index + 1);

    if (!username || !password) {
      throw createError({
        statusCode: 400,
        statusMessage: 'Invalid Basic Authorization',
      });
    }

    const foundUser = await Database.users.getByUsername(username);

    // always check to avoid timing attack
    const userHashPassword = foundUser?.password ?? null;
    const passwordValid = await isPasswordValid(password, userHashPassword);

    // can't login through basic auth if 2fa enabled
    if (!foundUser || !passwordValid || foundUser.totpVerified) {
      throw createError({
        statusCode: 401,
        statusMessage: 'Session failed',
      });
    }
    user = foundUser;
  } else {
    throw createError({
      statusCode: 401,
      statusMessage: 'Session failed. No Authorization',
    });
  }

  if (!user) {
    throw createError({
      statusCode: 401,
      statusMessage: 'Session failed. User not found',
    });
  }

  if (!user.enabled) {
    throw createError({
      statusCode: 403,
      statusMessage: 'User is disabled',
    });
  }

  return user;
}
