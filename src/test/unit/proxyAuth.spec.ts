import type { IncomingMessage, ServerResponse } from 'node:http';

import { createEvent, type H3Event } from 'h3';
import { describe, expect, test } from 'vitest';

import {
  getProxyAuthUsername,
  parseMaxClientsPerUser,
  parseProxyAdmins,
  parseProxyAuthHeader,
  parseProxyUsername,
} from '#server/utils/proxyAuth';
import { parseTrustedProxies } from '#server/utils/trustedProxy';
import { hasPermissions, roles } from '#shared/utils/permissions';

function createTestEvent(
  remoteAddress: string,
  headers: Record<string, string>
): H3Event {
  const req = {
    headers,
    socket: { remoteAddress },
    connection: { remoteAddress },
    url: '/',
    method: 'GET',
  } as unknown as IncomingMessage;
  return createEvent(req, {} as ServerResponse);
}

describe('parseProxyAuthHeader', () => {
  const proxies = parseTrustedProxies('127.0.0.1');

  test('is off when the setting is absent', () => {
    expect(parseProxyAuthHeader(undefined, proxies)).toBeUndefined();
    expect(parseProxyAuthHeader('  ', proxies)).toBeUndefined();
  });

  test('gives the header name in lower case', () => {
    expect(parseProxyAuthHeader(' X-Remote-User ', proxies)).toBe(
      'x-remote-user'
    );
  });

  test('refuses what is no header name', () => {
    expect(() => parseProxyAuthHeader('X Remote User', proxies)).toThrow(
      'Invalid PROXY_AUTH_HEADER'
    );
  });

  test('refuses to believe a header from anybody', () => {
    expect(() => parseProxyAuthHeader('X-Remote-User', [])).toThrow(
      'needs TRUSTED_PROXIES'
    );
  });
});

describe('parseProxyUsername', () => {
  test('takes plain user names, in lower case', () => {
    expect(parseProxyUsername('alice')).toBe('alice');
    expect(parseProxyUsername(' Alice.Smith ')).toBe('alice.smith');
    expect(parseProxyUsername('bob@example.com')).toBe('bob@example.com');
  });

  test('refuses everything else', () => {
    for (const value of [
      undefined,
      '',
      '   ',
      'two words',
      '-leading',
      'a,b',
      'x'.repeat(65),
      "o'brien",
      'alice\nbob',
    ]) {
      expect(parseProxyUsername(value)).toBeUndefined();
    }
  });
});

describe('parseProxyAdmins and parseMaxClientsPerUser', () => {
  test('admins: a list of user names', () => {
    expect(parseProxyAdmins(undefined)).toEqual([]);
    expect(parseProxyAdmins(' Alice, bob ,')).toEqual(['alice', 'bob']);
    expect(() => parseProxyAdmins('alice,two words')).toThrow(
      'Invalid user name in PROXY_AUTH_ADMINS'
    );
  });

  test('limit: a number, none by default', () => {
    expect(parseMaxClientsPerUser(undefined)).toBe(0);
    expect(parseMaxClientsPerUser('')).toBe(0);
    expect(parseMaxClientsPerUser(' 5 ')).toBe(5);
    expect(() => parseMaxClientsPerUser('five')).toThrow(
      'Invalid MAX_CLIENTS_PER_USER'
    );
    expect(() => parseMaxClientsPerUser('-1')).toThrow(
      'Invalid MAX_CLIENTS_PER_USER'
    );
  });
});

describe('getProxyAuthUsername', () => {
  const config = {
    header: 'x-remote-user',
    trustedProxies: parseTrustedProxies('127.0.0.1,10.0.0.0/24'),
  };

  test('believes the header from a trusted proxy', () => {
    const event = createTestEvent('127.0.0.1', { 'x-remote-user': 'Alice' });
    expect(getProxyAuthUsername(event, config)).toBe('alice');
    const fromNet = createTestEvent('10.0.0.7', { 'x-remote-user': 'bob' });
    expect(getProxyAuthUsername(fromNet, config)).toBe('bob');
  });

  test('ignores the header from anybody else', () => {
    const event = createTestEvent('192.0.2.10', { 'x-remote-user': 'alice' });
    expect(getProxyAuthUsername(event, config)).toBeUndefined();
  });

  test('is not fooled by a forwarded address', () => {
    // the peer is what counts, not what the peer says about itself
    const event = createTestEvent('192.0.2.10', {
      'x-remote-user': 'alice',
      'x-forwarded-for': '127.0.0.1',
    });
    expect(getProxyAuthUsername(event, config)).toBeUndefined();
  });

  test('knows nobody without the header, or with an unusable one', () => {
    expect(
      getProxyAuthUsername(createTestEvent('127.0.0.1', {}), config)
    ).toBeUndefined();
    expect(
      getProxyAuthUsername(
        createTestEvent('127.0.0.1', { 'x-remote-user': 'two words' }),
        config
      )
    ).toBeUndefined();
  });

  test('is off without a configured header', () => {
    const event = createTestEvent('127.0.0.1', { 'x-remote-user': 'alice' });
    expect(
      getProxyAuthUsername(event, { ...config, header: undefined })
    ).toBeUndefined();
  });
});

describe('what an ordinary user may do with clients', () => {
  const user = { id: 7, role: roles.CLIENT };
  const admin = { id: 1, role: roles.ADMIN };
  const own = { id: 20, userId: 7 };
  const foreign = { id: 21, userId: 8 };

  test('makes clients, and sees, switches and removes their own only', () => {
    expect(hasPermissions(user, 'clients', 'create')).toBe(true);
    for (const action of ['view', 'update', 'delete'] as const) {
      expect(hasPermissions(user, 'clients', action, own)).toBe(true);
      expect(hasPermissions(user, 'clients', action, foreign)).toBe(false);
    }
  });

  test('changes the settings of none, not even their own', () => {
    expect(hasPermissions(user, 'clients', 'edit', own)).toBe(false);
    expect(hasPermissions(user, 'clients', 'edit', foreign)).toBe(false);
    expect(hasPermissions(user, 'admin', 'any')).toBe(false);
  });

  test('an administrator does everything with every client', () => {
    for (const action of ['view', 'update', 'edit', 'delete'] as const) {
      expect(hasPermissions(admin, 'clients', action, foreign)).toBe(true);
    }
    expect(hasPermissions(admin, 'admin', 'any')).toBe(true);
  });
});
