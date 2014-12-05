// Package tlswrapper provides a simple combined HTTP/HTTPS server
// that steers clients to HTTPS and pins them there with HSTS.
//
// It is meant as a near drop-in replacement for a net/http.Server. It
// takes an http.Handler and a collection of TLS certs and keys. From
// that, it will serve both an HTTP and an HTTPS port.
//
// On the HTTPS port, it uses SNI to serve the appropriate certificate
// to clients, and passes requests through to the Handler. The passed
// ResponseWriter is preloaded with an HSTS header, which - if not
// deleted by the Handler - will instruct compliant browsers to always
// use HTTPS for that request's domain.
//
// On the HTTP port, requests made to domains for which the Server has
// a certificate are redirected to the HTTPS port. Requests to other
// domains are passed to InsecureHandler if provided, or 404'd by
// default.
//
// A few additional headers are also set to enforce stricter content
// security policies by default: disallowing iframe and plugin
// embedding, requiring same origin for other included content,
// blocking certain XSS attacks, and preventing browsers from getting
// creative with MIME type sniffing.
//
// An sample static content server is available in the static_content
// subdirectory.
package tlswrapper // import "gopkg.in/danderson/tlswrapper.v1"

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"path"
	"regexp"
	"strings"
	"time"
)

// getHostOnly strips out any port present in hostPort, returning just
// the host portion.
func getHostOnly(hostPort string) string {
	if host, _, err := net.SplitHostPort(hostPort); err == nil {
		return host
	} else {
		return hostPort
	}
}

// Server defines the parameters for running a combined HTTP/HTTPS
// server. The zero value is valid, albeit useless (it'll 404 all
// requests).
type Server struct {
	Handler         http.Handler // handler to invoke, http.DefaultServeMux if nil
	InsecureHandler http.Handler // handler to invoke for requests to unrecognized hosts on the non-TLS port.
	MaxHeaderBytes  int          // maximum size of request headers, DefaultMaxHeaderBytes if 0

	Certificates []tls.Certificate // certs to serve. Only requests to hosts with a cert will be passed to Handler.
	HSTSDuration time.Duration     // how long browsers should force TLS.

	httpsPortSuffix string
	hstsValue       string
	hostRegex       *regexp.Regexp
}

// LoadCertsFromDir populates Certificates with cert/key pairs loaded
// from disk. Every <name>.key with a corresponding <name>.pem will be
// loaded as one tls.Certificate.
func (s *Server) LoadCertsFromDir(certDir string) error {
	list, err := ioutil.ReadDir(certDir)
	if err != nil {
		return fmt.Errorf("listing directory '%s': %s", certDir, err)
	}

	certs := []tls.Certificate{}
	for _, ent := range list {
		if !strings.HasSuffix(ent.Name(), ".key") {
			continue
		}
		key := path.Join(certDir, ent.Name())
		pub := key[:len(key)-3] + "pem"
		cert, err := tls.LoadX509KeyPair(pub, key)
		if err != nil {
			return fmt.Errorf("loading keypair '%s.{pem,key}': %s", key[:len(key)-3], err)
		}
		certs = append(certs, cert)
	}

	s.Certificates = certs
	return nil
}

// ListenAndServe listens on the provided httpAddr and httpsAddr, then
// calls Handler/InsecureHandler as explained in the package
// docstring.
func (s *Server) ListenAndServe(httpAddr, httpsAddr string) error {
	_, port, err := net.SplitHostPort(httpsAddr)
	if err == nil && port != "443" {
		s.httpsPortSuffix = ":" + port
	}

	s.hstsValue = fmt.Sprintf("max-age=%d", int64(s.HSTSDuration.Seconds()))

	tlsConf := &tls.Config{
		Certificates:             s.Certificates,
		PreferServerCipherSuites: true,
		MinVersion:               tls.VersionTLS10,
	}
	tlsConf.BuildNameToCertificate()

	reStr := make([]string, 0, len(tlsConf.NameToCertificate))
	for host := range tlsConf.NameToCertificate {
		host = strings.Replace(host, ".", `\.`, -1)
		host = strings.Replace(host, "*", `[^.]+`, -1)
		reStr = append(reStr, host)
	}
	s.hostRegex, err = regexp.Compile(fmt.Sprintf("^(%s)$", strings.Join(reStr, "|")))
	if err != nil {
		return fmt.Errorf("compiling hosts regex: %s", err)
	}

	httpListener, err := net.Listen("tcp", httpAddr)
	if err != nil {
		return err
	}
	defer httpListener.Close()

	httpsListener, err := net.Listen("tcp", httpsAddr)
	if err != nil {
		return err
	}
	defer httpsListener.Close()

	errCh := make(chan error, 2)

	go func() {
		s := &http.Server{
			Addr:           httpAddr,
			Handler:        http.HandlerFunc(s.serveRedirect),
			MaxHeaderBytes: s.MaxHeaderBytes,
		}
		errCh <- s.Serve(httpListener)
	}()

	go func() {
		s := &http.Server{
			Addr:           httpsAddr,
			Handler:        http.HandlerFunc(s.serveSecure),
			MaxHeaderBytes: s.MaxHeaderBytes,
			TLSConfig:      tlsConf,
		}
		errCh <- s.Serve(tls.NewListener(httpsListener, tlsConf))
	}()

	return <-errCh
}

func (s *Server) serveRedirect(w http.ResponseWriter, r *http.Request) {
	if !s.hostRegex.MatchString(getHostOnly(r.Host)) {
		if s.InsecureHandler != nil {
			s.InsecureHandler.ServeHTTP(w, r)
		} else {
			http.NotFound(w, r)
		}
		return
	}

	r.URL.Scheme = "https"
	r.URL.Host = getHostOnly(r.Host)
	if s.httpsPortSuffix != "" {
		r.URL.Host += s.httpsPortSuffix
	}

	http.Redirect(w, r, r.URL.String(), http.StatusFound)
}

func (s *Server) serveSecure(w http.ResponseWriter, r *http.Request) {
	if !s.hostRegex.MatchString(getHostOnly(r.Host)) {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Strict-Transport-Security", s.hstsValue)
	w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-src 'none'; object-src 'none'")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	if s.Handler == nil {
		http.DefaultServeMux.ServeHTTP(w, r)
	} else {
		s.Handler.ServeHTTP(w, r)
	}
}
