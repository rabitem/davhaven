# Outbound HTTP and the egress policy

Everything the server sends over HTTP to the outside — webhook deliveries, OAuth token exchanges, calls to calendar
providers — goes through one port, `HttpClient`, and one adapter, `http-egress`. It is the only crate that depends on
an HTTP client library (reqwest with rustls), and it applies the **egress policy** inside every call, so that a URL a
tenant administrator or an attacker controls cannot be used to reach internal systems (SSRF). Tenants register
webhook URLs themselves, so this is a boundary, not a convenience.

## What every request goes through

1. **The URL, before anything is sent.** Only `https` (unless `allow_http`), at most 2048 characters, a host, no user
   or password in the URL. A host that is a literal address — in any notation: `2130706433`, `0x7f.1`, `0177.0.0.1`,
   `127.1`, `[::1]`, `[::ffff:127.0.0.1]` — is judged by the address rules below. Ports are free unless the
   deployment lists `allowed_ports`.
2. **The addresses, when the connection is made.** Host names are resolved by the client's own resolver, **once per
   connection**; the connection goes to the addresses of that answer and nowhere else, so a second lookup (DNS
   rebinding) cannot change the target between the check and the connection. If **any** address in the answer is
   denied, the whole answer is refused: a host that resolves to a public and a private address is not tried at all.
   The number of lookups that run at once is bounded (`max_concurrent_lookups`), because a lookup occupies a thread
   of the blocking pool until the resolver answers: names that never answer cannot starve the rest of the server.
3. **No redirects.** A `3xx` is returned as it is; the application treats it as a failure. No proxy from the
   environment is used.
4. **Limits, by purpose.** A connect timeout, a total timeout including the body, and a cap on the response size.
   The caller says what a request is for (`HttpPurpose`) and the limits follow: a **webhook** answer is read for its
   status only, so a longer body is **cut at the cap** and the delivery is still judged by its status (a receiver
   that echoes the request or answers with a page is not a failing receiver); an **OAuth** answer is a small token
   document and a **provider API** answer is a page of events with a larger cap and a longer timeout; for these
   two a body over the cap fails the request.
5. **Quiet errors.** Errors carry the kind of the failure (`rejected`, `unavailable`, `timeout`), never the URL, the
   query string, a header value or the body: webhook URLs and signatures are secrets.

## Which addresses are allowed

Only **global unicast** addresses. Everything else is classified and refused:

| Class | IPv4 | IPv6 |
| --- | --- | --- |
| unspecified | `0.0.0.0/8` | `::` |
| loopback | `127.0.0.0/8` | `::1` |
| private | `10/8`, `172.16/12`, `192.168/16` | site-local `fec0::/10` |
| link-local | `169.254/16` | `fe80::/10` |
| carrier-grade NAT | `100.64/10` | |
| unique-local | | `fc00::/7` |
| multicast, broadcast | `224/4`, `255.255.255.255` | `ff00::/8` |
| documentation, benchmarking | `192.0.2/24`, `198.51.100/24`, `203.0.113/24`, `198.18/15` | `2001:db8::/32` and friends |
| reserved | `192.0.0/24`, `192.88.99/24`, `240/4` | Teredo, discard-only and other special-purpose ranges |
| **cloud metadata** | `169.254.169.254`, `169.254.170.2`, `100.100.100.200`, `168.63.129.16`, `192.0.0.192`, … | `fd00:ec2::254` |

IPv6 addresses that **embed** an IPv4 address — IPv4-mapped (`::ffff:a.b.c.d`), IPv4-compatible (`::a.b.c.d`), NAT64
(`64:ff9b::/96`) and 6to4 (`2002::/16`) — are judged by the IPv4 rules of the embedded address, so `[::ffff:10.0.0.1]`
is as private as `10.0.0.1`.

## What a deployment can change

```toml
[plugins]
http_client = "egress"           # "recording" sends nothing and records requests (development, tests); refused in production

[security.egress]                # the table of the plugin `egress`
allow_http   = false             # permit the http scheme (tests, closed networks)
allow_cidrs  = ["10.20.0.0/16"]  # private ranges that may be called (a receiver inside the own network)
allowed_ports = [443]            # the ports a target may have; empty allows every port
allow_hosts  = ["hooks.internal.example"]   # host names whose addresses are allowed the same way (exact, lowercase, no wildcard)
deny_cidrs   = ["203.0.113.0/24"]           # further ranges that are denied; always wins over the allow lists
max_concurrent_lookups = 16      # host name lookups that may run at the same time
connect_timeout    = "5s"
total_timeout      = "10s"        # webhooks and OAuth
max_response_bytes = 65536        # a webhook answer is cut here (the status is what counts)
oauth_max_response_bytes        = 262144
provider_api_max_response_bytes = 8388608
provider_api_total_timeout      = "30s"
```

* `allow_cidrs` and `allow_hosts` permit non-global ranges; they never permit multicast, unspecified, broadcast or
  **metadata** addresses. `deny_cidrs` wins over both.
* `allowed_ports` keeps a tenant administrator from probing the other services of a public host: a deployment whose
  receivers all listen on 443 lists `[443]`. A URL without a port means 443 (`https`) or 80 (`http`).
* Webhook URLs are checked at registration (`HttpClient::validate_url`) with the same rules, including the addresses
  the host name resolves to **now**; the check is repeated on every delivery. `validate_url` **fails closed**: an
  adapter that does not implement it answers `Unsupported`, and registration is refused instead of trusting a URL
  nobody checked (the contract suite has a case for this). The refusal a tenant administrator sees is the same for
  every reason ("The URL is not allowed as a webhook target."), so the registration form cannot be used to probe the
  private DNS of the deployment one name at a time; the reason is in the log of the adapter.
* Unknown keys are errors, and a range or host that cannot be parsed stops the server at startup with the key named.

## Testing

`davhaven_port_tests::http_client` is the contract suite every `HttpClient` must pass: schemes, credentials in the
URL, a table of targets (ranges, encodings, IPv6 forms), the quiet errors (a failing call names neither the URL nor
the host in its text) and the fail-closed default of `validate_url`. The adapter's own tests add:

* the resolver cases: mixed answers, a lookup that changes between calls, and a bound on concurrent lookups that
  holds while the names never answer;
* the **rebinding tests**: a name that was public when the webhook was registered and answers with the loopback
  address when the delivery resolves it is refused (every send is judged on its own answer), and a send that
  resolved to an allowed address connects to that address and never looks the name up a second time (the scripted
  second answer, the metadata address, is not asked for);
* the redirect behavior against a real local server, the response caps of each purpose and the timeouts;
* every row of the classification table above.

The `recording` client (development and tests) applies the same URL rules to every request it records.
