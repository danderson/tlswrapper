# tlswrapper - A Go library for easier HTTPS serving

This package is meant as a near drop-in replacement for
net/http.Server, but serves both HTTP and HTTPS. HTTP requests are
steered to HTTPS, and HTTPS responses set good default content
security related headers to make the content served safer by default.

To get free TLS certificates, you can try
[StartSSL](https://www.startssl.com) or, starting mid-2015,
[Let's Encrypt](https://letsencrypt.org/).

## Features

- Selects the right certificate to present with SNI.
- Redirects requests made over HTTP to the HTTPS port.
- Only provides authoritative responses if it owns the request domain.
- Sets a number of HTTP headers to safer defaults before invoking your
  handler.

## Headers set by default

Before invoking `Server.Handler` on secure requests, tlswrapper sets a
number of response headers to defaults that tighten security. The
Handler may still edit/clear these headers if it wants to. The headers
set are:

- `Strict-Transport-Security`: tells compliant browsers to never use
  unencrypted transports for the requesting domain, for
  `Server.HSTSDuration` since the last time the header was seen.
- `Content-Security-Policy`: only allows loading resources (scripts,
  CSS, etc.) from the same origin, and completely disallows iframe and
  object embedding (i.e. flash and other such plugins).
- `X-Frame-Options: DENY`: an older, less flexible version of
  `Content-Security-Policy`, disallows iframe embedding on the
  page. This mainly benefits IE 8 through 10, which don't understand
  `Content-Security-Policy`.
- `X-Content-Type-Options: nosniff`: disables client-side MIME type
  sniffing. Compliant browsers will not second-guess the Content-Type
  set by your Handler.
- `X-XSS-Protection`: configures XSS detection and blocking on IE,
  Chrome and Webkit browsers to not display any of the page if an XSS
  attack is detected.

## Using it

tlswrapper uses [gopkg.in](https://gopkg.in/danderson/tlswrapper.v1) for versioning.

Usage:

```go
import "gopkg.in/danderson/tlswrapper.v1"
```

For more information, check out the [API documentation](https://godoc.org/gopkg.in/danderson/tls-server.v1).
