[![Go](https://github.com/muety/caddy-remote-host/workflows/Go/badge.svg)](https://github.com/muety/caddy-remote-host/actions)

# caddy-remote-host

Caddy plugin to match a request's client IP against A and AAAA DNS records of a host name (analogously
to [`remote_ip`](https://caddyserver.com/docs/caddyfile/matchers#remote-ip)). Can be useful to restrict route access to
a client, that uses dynamic DNS. Uses the host machine's local DNS resolver (
uses [LookupIP](https://pkg.go.dev/net?utm_source=godoc#LookupIP) internally).

## Usage

```
remote_host [forwarded] <hosts...>
```

Accepts valid host names. If the first argument is `forwarded`, then the first IP in the `X-Forwarded-For` request
header, if present, will be preferred as the reference IP, rather than the immediate peer's IP, which is the default.

Multiple `remote_host` matchers will be OR'ed together.

### Example

Match requests from a client, whose IPv4 or IPv6 address is the same as what `ddns.example.org` resolves to.

```
remote_host ddns.example.org
```

## License

Apache 2.0