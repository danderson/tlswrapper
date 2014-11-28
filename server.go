package tls_server

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

type Server struct {
	Handler        http.Handler  // handler to invoke, http.DefaultServeMux if nil
	ReadTimeout    time.Duration // maximum duration before timing out read of the request
	WriteTimeout   time.Duration // maximum duration before timing out write of the response
	MaxHeaderBytes int           // maximum size of request headers, DefaultMaxHeaderBytes if 0

	Certificates []tls.Certificate // certs to serve. Only requests to hosts with a cert will be passed to Handler.
	HSTSDuration time.Duration     // how long browsers should force TLS.

	httpsPortSuffix string
	hstsValue       string
	hostRegex       *regexp.Regexp
}

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

	if s.Handler == nil {
		s.Handler = http.DefaultServeMux
	}

	errCh := make(chan error, 2)

	go func() {
		s := &http.Server{
			Addr:           httpAddr,
			Handler:        http.HandlerFunc(s.serveRedirect),
			ReadTimeout:    s.ReadTimeout,
			WriteTimeout:   s.WriteTimeout,
			MaxHeaderBytes: s.MaxHeaderBytes,
		}
		errCh <- s.Serve(httpListener)
	}()

	go func() {
		s := &http.Server{
			Addr:           httpsAddr,
			Handler:        http.HandlerFunc(s.serveSecure),
			ReadTimeout:    s.ReadTimeout,
			WriteTimeout:   s.WriteTimeout,
			MaxHeaderBytes: s.MaxHeaderBytes,
			TLSConfig:      tlsConf,
		}
		errCh <- s.Serve(tls.NewListener(httpsListener, tlsConf))
	}()

	return <-errCh
}

func (s *Server) serveRedirect(w http.ResponseWriter, r *http.Request) {
	if !s.hostRegex.MatchString(getHostOnly(r.Host)) {
		http.NotFound(w, r)
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
	s.Handler.ServeHTTP(w, r)
}
