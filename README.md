[![Go](https://github.com/muety/caddy-remote-host/workflows/Go/badge.svg)](https://github.com/muety/caddy-remote-host/actions)
![Coding Time](https://img.shields.io/endpoint?url=https://wakapi.dev/api/compat/shields/v1/n1try/interval:any/project:caddy-remote-host&color=blue&label=coding%20time)

# caddy-remote-host

Caddy plugin to match a request's client IP against A and AAAA DNS records of a host name (analogously
to [`remote_ip`](https://caddyserver.com/docs/caddyfile/matchers#remote-ip)). Can be useful to restrict route access to
a client, that uses dynamic DNS. Uses the host machine's local DNS resolver (uses [LookupIP](https://pkg.go.dev/net?utm_source=godoc#LookupIP) internally).

## Usage

```
remote_host [forwarded] [nocache] <hosts...>
```

Accepts valid host names. If `forwarded` is given as an argument, then the first IP in the `X-Forwarded-For` request
header, if present, will be preferred as the reference IP, rather than the immediate peer's IP, which is the default.
If `nocache` is given as an argument, this module will not cache DNS responses and instead resolve the given hosts' for
every request. By default, responses are cached for 60 seconds, regardless of the DNS record's time-to-live (TTL).

Multiple `remote_host` matchers will be OR'ed together.

### Example

Match requests from a client, whose IPv4 or IPv6 address is the same as what `ddns.example.org` resolves to.

```
remote_host ddns.example.org
```

## License

Apache 2.0
