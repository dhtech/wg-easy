import { createError, defineEventHandler } from 'h3';

import { SERVER_DEBUG, WG_ENV } from '#server/utils/config';
import { useWGSession } from '#server/utils/session';

export default defineEventHandler(async (event) => {
  if (WG_ENV.PROXY_AUTH_HEADER) {
    // nothing of ours to end: the login is the proxy's
    return { success: true };
  }

  const session = await useWGSession(event);
  const sessionId = session.id;

  if (sessionId === undefined) {
    throw createError({
      statusCode: 401,
      statusMessage: 'Not logged in',
    });
  }

  await session.clear();

  SERVER_DEBUG(`Deleted Session: ${sessionId}`);
  return { success: true };
});
