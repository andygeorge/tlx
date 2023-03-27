package main

import (
	"crypto/tls"
	"fmt"
	"time"

	go_arg "github.com/alexflint/go-arg"
)

var args struct {
	Domain string `arg:"required,positional"`
	Port   string `arg:"positional" default:"443"`
}

func main() {
	now := time.Now()
	go_arg.MustParse(&args)
	conf := &tls.Config{InsecureSkipVerify: true}

	conn, err := tls.Dial("tcp", args.Domain+":"+args.Port, conf)
	if err != nil {
		panic(err)
	}

	defer conn.Close()
	cert := conn.ConnectionState().PeerCertificates[0]
	domain := cert.Subject.String()[3:]
	expireDate, err := time.Parse("2006-01-02", cert.NotAfter.Format("2006-01-02"))
	if err != nil {
		panic(err)
	}

	days := expireDate.Sub(now).Hours() / 24

	fmt.Printf(
		"%s expires %s (in %.0f days)\n",
		domain,
		cert.NotAfter.Format("2006-01-02"),
		days,
	)
}
