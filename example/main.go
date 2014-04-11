package main

import (
	"bitbucket.org/danderson/gofer"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"
)

var (
	listenHttps   = flag.String("listen-https", ":1443", "Address to listen on for HTTPS")
	listenHttp    = flag.String("listen-http", ":1080", "Address to listen on for HTTP")
	certDir       = flag.String("certdir", "", "Directory containing certs and keys")
	socketTimeout = flag.Duration("socket-timeout", 10*time.Second, "Timeout on HTTP server socket operations")
	hstsDuration  = flag.Duration("hsts-duration", 365*24*time.Hour, "HSTS enforcement time to return to clients")
)

func main() {
	flag.Parse()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprintf(w, "Hello world! Your request:\n\n%#v", r)
	})

	s := &gofer.Server{
		ReadTimeout:  *socketTimeout,
		WriteTimeout: *socketTimeout,
		HSTSDuration: *hstsDuration,
	}
	if err := s.LoadCertsFromDir(*certDir); err != nil {
		log.Fatalln(err)
	}

	log.Fatalln(s.ListenAndServe(*listenHttp, *listenHttps))
}
