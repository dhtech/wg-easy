import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { afterEach, beforeEach, describe, expect, test } from 'vitest';

import {
  createProxyAdminsFile,
  parseMaxClientsPerUser,
  parseProxyAdmins,
  parseProxyAdminsText,
  parseProxyAuthHeader,
  parseProxyUsername,
  proxyUsernameFrom,
} from '#server/utils/proxyAuth';
import { parseTrustedProxies } from '#server/utils/trustedProxy';
import { hasPermissions, roles } from '#shared/utils/permissions';

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

describe('the administrators file', () => {
  let dir: string;
  let file: string;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wg-easy-admins-'));
    file = path.join(dir, 'admins');
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  test('text: names per line or comma separated, comments, no repeats', () => {
    expect(
      parseProxyAdminsText('# the leaders\nAlice\nbob, carol # two\n\nalice\n')
    ).toEqual(['alice', 'bob', 'carol']);
  });

  test('text: what is no user name is skipped, the rest stays', () => {
    expect(parseProxyAdminsText('alice\ntwo words\n-x\nbob\n')).toEqual([
      'alice',
      'bob',
    ]);
    expect(parseProxyAdminsText('')).toEqual([]);
  });

  test('no file configured: nobody', () => {
    expect(createProxyAdminsFile(undefined)()).toEqual([]);
  });

  test('a missing file names nobody, and is found when it appears', () => {
    const admins = createProxyAdminsFile(file);
    expect(admins()).toEqual([]);
    fs.writeFileSync(file, 'alice\n');
    expect(admins()).toEqual(['alice']);
  });

  test('follows the file when it is replaced', () => {
    fs.writeFileSync(file, 'alice\n');
    const admins = createProxyAdminsFile(file);
    expect(admins()).toEqual(['alice']);
    // replaced the way careful writers do it: a new file moved in place
    const next = path.join(dir, 'admins.new');
    fs.writeFileSync(next, 'bob\ncarol\n');
    fs.renameSync(next, file);
    expect(admins()).toEqual(['bob', 'carol']);
  });

  test('a file that goes away names nobody again', () => {
    fs.writeFileSync(file, 'alice\n');
    const admins = createProxyAdminsFile(file);
    expect(admins()).toEqual(['alice']);
    fs.rmSync(file);
    expect(admins()).toEqual([]);
  });
});

describe('proxyUsernameFrom', () => {
  const config = {
    header: 'x-remote-user',
    trustedProxies: parseTrustedProxies('127.0.0.1,10.0.0.0/24,::1'),
  };

  test('believes the header from a trusted proxy', () => {
    expect(proxyUsernameFrom('127.0.0.1', 'Alice', config)).toBe('alice');
    expect(proxyUsernameFrom('10.0.0.7', 'bob', config)).toBe('bob');
    expect(proxyUsernameFrom('::1', 'carol', config)).toBe('carol');
  });

  test('ignores the header from anybody else', () => {
    expect(proxyUsernameFrom('192.0.2.10', 'alice', config)).toBeUndefined();
    expect(proxyUsernameFrom('10.0.1.7', 'alice', config)).toBeUndefined();
    expect(proxyUsernameFrom('2001:db8::1', 'alice', config)).toBeUndefined();
  });

  test('ignores it when the peer is not known', () => {
    expect(proxyUsernameFrom(undefined, 'alice', config)).toBeUndefined();
    expect(proxyUsernameFrom('', 'alice', config)).toBeUndefined();
    expect(
      proxyUsernameFrom('not an address', 'alice', config)
    ).toBeUndefined();
  });

  test('knows nobody without the header, or with an unusable one', () => {
    expect(proxyUsernameFrom('127.0.0.1', undefined, config)).toBeUndefined();
    expect(proxyUsernameFrom('127.0.0.1', 'two words', config)).toBeUndefined();
  });

  test('is off without a configured header', () => {
    expect(
      proxyUsernameFrom('127.0.0.1', 'alice', { ...config, header: undefined })
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
