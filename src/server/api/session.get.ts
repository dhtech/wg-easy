import { createError, defineEventHandler } from 'h3';
import type { H3Event } from 'h3';

import Database from '#server/utils/Database';
import { WG_ENV } from '#server/utils/config';
import { getCurrentUser, useWGSession } from '#server/utils/session';
import type { SharedPublicUser } from '#shared/utils/permissions';

async function sessionUser(event: H3Event) {
  if (WG_ENV.PROXY_AUTH_HEADER) {
    // proxy authentication: who it is comes with every request
    return getCurrentUser(event);
  }

  const session = await useWGSession(event);

  if (!session.data.userId || session.data.pendingLogin) {
    // not logged in
    throw createError({
      statusCode: 401,
      statusMessage: 'Not authenticated',
    });
  }

  const user = await Database.users.get(session.data.userId);
  if (!user) {
    throw createError({
      statusCode: 404,
      statusMessage: 'Not found in Database',
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

export default defineEventHandler(async (event) => {
  const user = await sessionUser(event);

  return {
    id: user.id,
    role: user.role,
    username: user.username,
    name: user.name,
    email: user.email,
    totpVerified: user.totpVerified,
    oauthProvider: user.oauthProvider,
    hasPassword: user.password !== null,
  } satisfies SharedPublicUser;
});
