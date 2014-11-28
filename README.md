# tlswrapper - A Go library for easier HTTPS serving

This package is meant as a near drop-in replacement for
net/http.Server, but serves both HTTP and HTTPS. HTTP requests are
steered to HTTPS, and HTTPS responses set the appropriate HSTS header
to pin clients to HTTPS.

To get free TLS certificates, you can try
[StartSSL](https://www.startssl.com) or, starting mid-2015,
[Let's Encrypt](https://letsencrypt.org/).

## Features

- Selects the right certificate to present with SNI.
- Sets HSTS in responses to pin compliant clients to a secure transport.
- Redirects requests made over HTTP to the HTTPS port.
- Only provides authoritative responses if it owns the request domain.

## Using it

Kingpin uses [gopkg.in](https://gopkg.in/danderson/tlswrapper.v1) for versioning.

Usage:

```go
import "gopkg.in/danderson/tlswrapper.v1"
```

For more information, check out the [API documentation](https://godoc.org/gopkg.in/danderson/tls-server.v1).
