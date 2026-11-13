import { createError, readValidatedBody } from 'h3';

import Database from '#server/utils/Database';
import WireGuard from '#server/utils/WireGuard';
import { WG_ENV } from '#server/utils/config';
import { definePermissionEventHandler } from '#server/utils/handler';
import { validateZod } from '#server/utils/types';
import { HooksUpdateSchema } from '#db/repositories/hooks/types';

export default definePermissionEventHandler(
  'admin',
  'any',
  async ({ event }) => {
    if (WG_ENV.DISABLE_HOOKS) {
      throw createError({
        statusCode: 403,
        statusMessage: 'Hooks are disabled on this server (DISABLE_HOOKS)',
      });
    }
    const data = await readValidatedBody(
      event,
      validateZod(HooksUpdateSchema, event)
    );
    await Database.hooks.update(data);
    await WireGuard.saveConfig();
    return { success: true };
  }
);
