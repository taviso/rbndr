# rbndr
Simple DNS Rebinding Service

This is a very simple, non-conforming, name server for testing software against DNS rebinding vulnerabilities. The server responds to queries by randomly selecting one of the addresses specified and returning it as the answer with a very low ttl.

https://en.wikipedia.org/wiki/DNS_rebinding

You would use this if you have a service that uses "preflight" checks to verify security. For example, consider a (fictional) browser plugin that has an api like this:

```
AllowUntrustedAccess("foobar.com");
SendArbitraryRequests("foobar.com");
```

And `AllowUntrustedAccess()` simply sends a preflight HTTP request to the host:

```
GET /is_it_ok_to_disable_security HTTP/1.1
```

If the service returns 200, then the plugin allows the hostpage complete access to that domain. This might be a security vulnerability, because you can specify a rbndr hostname that will switch between a host you control and a host you don't. The plugin might allow complete access to an arbitrary ip address (e.g. an internal service, or localhost) even if that service would not normally permit the preflight check.

For software that is vulnerable to this bug, rbndr is an easy way to test. If the software associates the result with the *hostname* and not the ip address, then you can grant yourself access to any ip address.

The format for hostnames is simply

```
<ipv4 in base-16>.<ipv4 in base-16>.rbndr.us
```

But you can use this website to convert from dotted quads if you prefer:

https://lock.cmpxchg8b.com/rebinder.html


For example, to switch between `127.0.0.1` and `192.168.0.1` you would encode them as dwords, and then use:

```
7f000001.c0a80001.rbndr.us
```

Let's test it out:

```
$ host 7f000001.c0a80001.rbndr.us
7f000001.c0a80001.rbndr.us has address 192.168.0.1
$ host 7f000001.c0a80001.rbndr.us
7f000001.c0a80001.rbndr.us has address 192.168.0.1
$ host 7f000001.c0a80001.rbndr.us
7f000001.c0a80001.rbndr.us has address 192.168.0.1
$ host 7f000001.c0a80001.rbndr.us
7f000001.c0a80001.rbndr.us has address 127.0.0.1
$ host 7f000001.c0a80001.rbndr.us
7f000001.c0a80001.rbndr.us has address 127.0.0.1
$ host 7f000001.c0a80001.rbndr.us
7f000001.c0a80001.rbndr.us has address 192.168.0.1
$ host 7f000001.c0a80001.rbndr.us
7f000001.c0a80001.rbndr.us has address 127.0.0.1
$ host 7f000001.c0a80001.rbndr.us
7f000001.c0a80001.rbndr.us has address 127.0.0.1
$ host 7f000001.c0a80001.rbndr.us
7f000001.c0a80001.rbndr.us has address 192.168.0.1

```

As you can see, the server randomly returns one of the addresses.

