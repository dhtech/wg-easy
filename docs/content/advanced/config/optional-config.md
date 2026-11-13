---
title: Optional Configuration
---

You can set these environment variables to configure the container. They are not required, but can be useful in some cases.

| Env                     | Default   | Example                     | Description                                                     |
| ----------------------- | --------- | --------------------------- | --------------------------------------------------------------- |
| `PORT`                  | `51821`   | `6789`                      | TCP port for Web UI.                                            |
| `HOST`                  | `0.0.0.0` | `localhost`                 | IP address web UI binds to.                                     |
| `INSECURE`              | `false`   | `true`                      | If access over http is allowed                                  |
| `DISABLE_IPV6`          | `false`   | `true`                      | If IPv6 support should be disabled                              |
| `DISABLE_VERSION_CHECK` | `false`   | `true`                      | If wg-easy should check for new updates                         |
| `TRUSTED_PROXIES`       |           | `172.18.0.2,fd00:1234::/64` | Proxy IP addresses or CIDRs allowed to forward request metadata |
| `WG_INTERFACE`          | `wg0`     | `wg1`                       | Name of the WireGuard interface                                 |
| `DISABLE_HOOKS`         | `false`   | `true`                      | Never run hooks or iptables: the host manages its own firewall  |

/// note | IPv6 Caveats

Disabling IPv6 will disable the creation of the default IPv6 firewall rules and won't add a IPv6 address to the interface and clients.

You will however still see a IPv6 address in the Web UI, but it won't be used.

This option can be removed in the future, as more devices support IPv6.

///

## Trusted Proxies

Set `TRUSTED_PROXIES` when wg-easy runs behind a reverse proxy and needs to use
the original host. Multiple IPv4 or IPv6 addresses and CIDRs can be provided as
a comma-separated list:

```yaml
environment:
    - TRUSTED_PROXIES=172.18.0.2,fd00:1234::/64
```

Only add the source addresses used by your reverse proxy. wg-easy only uses
`X-Forwarded-Host` and `X-Forwarded-For` when the request comes from one of
these addresses. The forwarded client address is included in security logs so
that tools such as CrowdSec can identify failed authentication attempts. The
request protocol remains controlled by `INSECURE`. Invalid addresses prevent
wg-easy from starting so that configuration errors are not silently ignored.
Restart the container after changing this setting.

## WireGuard Interface

Set `WG_INTERFACE` to specify a custom interface name, useful if you are running multiple wg-easy instances on the same host with `network_mode: host`:

```yaml
environment:
    - WG_INTERFACE=wg1
```

## Disable Hooks

By default wg-easy manages the firewall for you: the interface's `PostUp` and
`PostDown` hooks add and remove iptables rules (NAT and forwarding), an
administrator can edit those hooks in the Web UI, and the Per-Client Firewall
adds further iptables rules.

Set `DISABLE_HOOKS` when the firewall and the routing of the host belong to
somebody else, for example a host with its own nftables ruleset and
`network_mode: host`:

```yaml
environment:
    - DISABLE_HOOKS=true
```

With it

- no `PreUp`, `PostUp`, `PreDown` or `PostDown` line is written into the
  interface's configuration, whatever the database holds
- wg-easy never runs `iptables` or `ip6tables`
- changing the hooks and switching the Per-Client Firewall on are refused,
  for administrators too

You then have to allow and route the tunnel's traffic yourself: forwarding
(`net.ipv4.ip_forward`), a rule that lets packets from the WireGuard
interface through, the WireGuard port, and NAT if the clients' addresses are
not routed to the host.

/// warning | Hooks are commands

A hook is a shell command that runs as root inside the container. With
`network_mode: host` and `NET_ADMIN` that is root over the host's network:
whoever can edit a hook can replace the host's firewall. If your
administrators should not have that power, set `DISABLE_HOOKS`.

///
