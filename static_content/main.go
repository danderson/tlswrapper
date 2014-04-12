package main

import (
	"bitbucket.org/danderson/tls_server"
	"flag"
	"log"
	"net/http"
	"strings"
	"time"
)

var (
	roots         = flag.String("roots", "", "Directories to serve")
	listenHttps   = flag.String("listen-https", ":443", "Address to listen on for HTTPS")
	listenHttp    = flag.String("listen-http", ":80", "Address to listen on for HTTP")
	certDir       = flag.String("certdir", "", "Directory containing certs and keys")
	socketTimeout = flag.Duration("socket-timeout", 10*time.Second, "Timeout on HTTP server socket operations")
	hstsDuration  = flag.Duration("hsts-duration", 365*24*time.Hour, "HSTS enforcement time to return to clients")
)

func main() {
	flag.Parse()

	if *roots == "" {
		log.Fatalln("Please specify -root")
	}

	splitRoots := strings.Split(*roots, ",")
	for _, root := range splitRoots {
		path := strings.Split(root, ":")
		if len(path) != 2 {
			log.Fatalf("Bad root spec: %s", root)
		}
		http.Handle(path[0]+"/", http.FileServer(http.Dir(path[1])))
	}

	s := &tls_server.Server{
		ReadTimeout:  *socketTimeout,
		WriteTimeout: *socketTimeout,
		HSTSDuration: *hstsDuration,
	}
	if err := s.LoadCertsFromDir(*certDir); err != nil {
		log.Fatalln(err)
	}

	log.Fatalln(s.ListenAndServe(*listenHttp, *listenHttps))
}
