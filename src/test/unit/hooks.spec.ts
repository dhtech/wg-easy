import { describe, expect, test, vi } from 'vitest';

import { wg } from '#server/utils/wgHelper';
import type { HooksType } from '#db/repositories/hooks/types';
import type { InterfaceType } from '#db/repositories/interface/types';

vi.mock('#server/utils/config', () => ({
  WG_ENV: { WG_EXECUTABLE: 'wg', PORT: '51821' },
}));

const wgInterface = {
  name: 'wg0',
  device: 'eth0',
  port: 51820,
  privateKey: 'private-key',
  publicKey: 'public-key',
  ipv4Cidr: '10.8.0.0/24',
  ipv6Cidr: 'fdcc:ad94:bacf:61a4::cafe:0/112',
  mtu: 1420,
  routingTable: 'auto',
} as unknown as InterfaceType;

const hooks = {
  id: 'wg0',
  preUp: 'echo pre-up {{device}}',
  postUp:
    'iptables -t nat -A POSTROUTING -s {{ipv4Cidr}} -o {{device}} -j MASQUERADE',
  preDown: 'echo pre-down',
  postDown: 'nft flush ruleset',
} as unknown as HooksType;

const HOOK_LINE = /^\s*(PreUp|PostUp|PreDown|PostDown)\s*=/m;

describe('the hooks in the interface configuration', () => {
  test('are written by default, with the values filled in', () => {
    const config = wg.generateServerInterface(wgInterface, hooks, {
      enableIpv6: false,
    });

    expect(config).toContain('PreUp = echo pre-up eth0');
    expect(config).toContain(
      'PostUp = iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE'
    );
    expect(config).toContain('PostDown = nft flush ruleset');
  });

  test('are not written with disableHooks, whatever the database holds', () => {
    const config = wg.generateServerInterface(wgInterface, hooks, {
      enableIpv6: false,
      disableHooks: true,
    });

    expect(config).not.toMatch(HOOK_LINE);
    expect(config).not.toContain('iptables');
    expect(config).not.toContain('nft');
    // the interface itself is all there
    expect(config).toContain('[Interface]');
    expect(config).toContain('Address = 10.8.0.1/24');
    expect(config).toContain('ListenPort = 51820');
    expect(config).toContain('Table = auto');
  });
});
