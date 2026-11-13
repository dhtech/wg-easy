import { createError, readValidatedBody } from 'h3';

import Database from '#server/utils/Database';
import WireGuard from '#server/utils/WireGuard';
import { WG_ENV } from '#server/utils/config';
import { definePermissionEventHandler } from '#server/utils/handler';
import { validateZod } from '#server/utils/types';
import { roles } from '#shared/utils/permissions';
import { ClientCreateSchema } from '#db/repositories/client/types';

export default definePermissionEventHandler(
  'clients',
  'create',
  async ({ event, user }) => {
    const { name, expiresAt } = await readValidatedBody(
      event,
      validateZod(ClientCreateSchema, event)
    );

    // the address pool is everybody's: an ordinary user gets a share
    if (user.role !== roles.ADMIN && WG_ENV.MAX_CLIENTS_PER_USER > 0) {
      const own = await Database.clients.getAllForUser(user.id, {});
      if (own.length >= WG_ENV.MAX_CLIENTS_PER_USER) {
        throw createError({
          statusCode: 403,
          statusMessage: `Client limit reached (${WG_ENV.MAX_CLIENTS_PER_USER})`,
        });
      }
    }

    // the client belongs to who made it
    const result = await Database.clients.create({ name, expiresAt }, user.id);
    await WireGuard.saveConfig();

    const clientId = result[0]!.clientId;
    return { success: true, clientId };
  }
);
