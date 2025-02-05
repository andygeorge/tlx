package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	go_arg "github.com/alexflint/go-arg"
)

const (
	dayFormat = "2006-01-02 15:04 MST" // Using Go's reference time format
	version   = "1.2.0"
)

type args struct {
	Domain string `arg:"required,positional" help:"Domain name to check"`
	Port   string `arg:"positional" default:"443" help:"Port number (default: 443)"`
}

func (args) Version() string {
	return fmt.Sprintf("tlx %s", version)
}

type CertChecker struct {
	domain string
	port   string
	config *tls.Config
}

func NewCertChecker(domain, port string) *CertChecker {
	return &CertChecker{
		domain: domain,
		port:   port,
		config: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12, // Enforce minimum TLS version
		},
	}
}

func (c *CertChecker) Check() (*time.Time, string, error) {
	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%s", c.domain, c.port), c.config)
	if err != nil {
		return nil, "", fmt.Errorf("failed to establish TLS connection: %w", err)
	}
	defer conn.Close()

	// Get the peer certificate
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, "", fmt.Errorf("no certificates found")
	}

	cert := certs[0]
	domain := strings.TrimPrefix(cert.Subject.String(), "CN=")

	return &cert.NotAfter, domain, nil
}

func calculateDaysRemaining(expireDate time.Time) float64 {
	return time.Until(expireDate).Hours() / 24
}

func main() {
	var args args
	go_arg.MustParse(&args)

	checker := NewCertChecker(args.Domain, args.Port)
	expireDate, domain, err := checker.Check()
	if err != nil {
		log.Fatalf("Error checking certificate: %v", err)
	}

	daysRemaining := calculateDaysRemaining(*expireDate)

	// Add color coding based on remaining days
	var output string
	switch {
	case daysRemaining <= 7:
		output = "\033[31m" // Red
	case daysRemaining <= 30:
		output = "\033[33m" // Yellow
	default:
		output = "\033[32m" // Green
	}

	fmt.Printf("%s%s expires %s (in %.0f days)\033[0m\n",
		output,
		domain,
		expireDate.Format(dayFormat),
		daysRemaining,
	)

	// Exit with status code 1 if certificate expires within 7 days
	if daysRemaining <= 7 {
		os.Exit(1)
	}
}
