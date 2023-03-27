package tlx

import (
	"crypto/tls"
	"fmt"
	"os"
)

func main() {
	args := os.Args[1:]
	domain := "google.com"
	port := "443"

	if len(args) > 0 {
		domain = args[0]
	}
	if len(args) > 1 {
		port = args[1]
	}

	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	conn, err := tls.Dial("tcp", domain+":"+port, conf)
	if err != nil {
		panic(err)
	}

	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	for _, cert := range certs {
		fmt.Println(cert.NotAfter.Format("2006-01-02"))
	}
}
