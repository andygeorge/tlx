package main

import (
	"crypto/tls"
	"fmt"
	"time"

	go_arg "github.com/alexflint/go-arg"
)

const (
	DayFormat string = "2006-01-02 15:04 MST"
	Version   string = "1.0.0"
)

type args struct {
	Domain string `arg:"required,positional"`
	Port   string `arg:"positional" default:"443"`
}

func (args) Version() string {
	return "tlx " + Version
}

func main() {
	now := time.Now()

	var args args
	go_arg.MustParse(&args)

	tls_config := &tls.Config{InsecureSkipVerify: true}

	conn, err := tls.Dial("tcp", args.Domain+":"+args.Port, tls_config)
	if err != nil {
		panic(err)
	}

	defer conn.Close()
	cert := conn.ConnectionState().PeerCertificates[0]
	domain := cert.Subject.String()[3:]
	expireDate, err := time.Parse(DayFormat, cert.NotAfter.Format(DayFormat))
	if err != nil {
		panic(err)
	}

	days := expireDate.Sub(now).Hours() / 24

	fmt.Printf(
		"%s expires %s (in %.0f days)\n",
		domain,
		cert.NotAfter.Format(DayFormat),
		days,
	)
}
