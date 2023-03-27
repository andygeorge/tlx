package main

import (
	"crypto/tls"
	"fmt"

	go_arg "github.com/alexflint/go-arg"
)

var args struct {
	Domain string `arg:"required,positional"`
	Port   string `arg:"positional" default:"443"`
}

func main() {
	go_arg.MustParse(&args)

	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	conn, err := tls.Dial("tcp", args.Domain+":"+args.Port, conf)
	if err != nil {
		panic(err)
	}

	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	for _, cert := range certs {
		fmt.Println(cert.NotAfter.Format("2006-01-02"))
	}
}
