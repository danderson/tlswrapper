package main

import (
	"bitbucket.org/danderson/tls_server"
	"flag"
	"log"
	"net/http"
	"time"
)

var (
	root          = flag.String("root", "", "Directory to serve")
	listenHttps   = flag.String("listen-https", ":443", "Address to listen on for HTTPS")
	listenHttp    = flag.String("listen-http", ":80", "Address to listen on for HTTP")
	certDir       = flag.String("certdir", "", "Directory containing certs and keys")
	socketTimeout = flag.Duration("socket-timeout", 10*time.Second, "Timeout on HTTP server socket operations")
	hstsDuration  = flag.Duration("hsts-duration", 365*24*time.Hour, "HSTS enforcement time to return to clients")
)

func main() {
	flag.Parse()

	if *root == "" {
		log.Fatalln("Please specify -root")
	}

	s := &tls_server.Server{
		Handler:      http.FileServer(http.Dir(*root)),
		ReadTimeout:  *socketTimeout,
		WriteTimeout: *socketTimeout,
		HSTSDuration: *hstsDuration,
	}
	if err := s.LoadCertsFromDir(*certDir); err != nil {
		log.Fatalln(err)
	}

	log.Fatalln(s.ListenAndServe(*listenHttp, *listenHttps))
}
