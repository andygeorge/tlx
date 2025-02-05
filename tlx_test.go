package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	goarg "github.com/alexflint/go-arg"
)

func TestVersion(t *testing.T) {
	tests := []struct {
		name     string
		expected string
	}{
		{
			name:     "correct version string",
			expected: "tlx " + version,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var a args
			if got := a.Version(); got != tt.expected {
				t.Errorf("Version() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestParseArgs(t *testing.T) {
	originalArgs := os.Args
	defer func() { os.Args = originalArgs }()

	tests := []struct {
		name        string
		args        []string
		wantDomain  string
		wantPort    string
		shouldError bool
	}{
		{
			name:       "domain and port specified",
			args:       []string{"prog", "example.com", "8443"},
			wantDomain: "example.com",
			wantPort:   "8443",
		},
		{
			name:       "domain only - default port",
			args:       []string{"prog", "example.com"},
			wantDomain: "example.com",
			wantPort:   "443",
		},
		{
			name:        "no arguments",
			args:        []string{"prog"},
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Args = tt.args
			var got args
			err := goarg.Parse(&got)

			if tt.shouldError {
				if err == nil {
					t.Error("Parse() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("Parse() unexpected error: %v", err)
			}

			if got.Domain != tt.wantDomain {
				t.Errorf("Parse() domain = %v, want %v", got.Domain, tt.wantDomain)
			}
			if got.Port != tt.wantPort {
				t.Errorf("Parse() port = %v, want %v", got.Port, tt.wantPort)
			}
		})
	}
}

type testServer struct {
	listener net.Listener
	cert     tls.Certificate
}

func createTestCert(t *testing.T, domain string, notBefore, notAfter time.Time) (tls.Certificate, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: domain,
		},
		DNSNames:              []string{domain},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privateKey,
	}, nil
}

func newTestServer(t *testing.T, domain string, notBefore, notAfter time.Time) (*testServer, error) {
	cert, err := createTestCert(t, domain, notBefore, notAfter)
	if err != nil {
		return nil, err
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", config)
	if err != nil {
		return nil, err
	}

	server := &testServer{
		listener: listener,
		cert:     cert,
	}

	go server.serve()
	return server, nil
}

func (s *testServer) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			buffer := make([]byte, 1)
			c.Read(buffer)
		}(conn)
	}
}

func (s *testServer) close() {
	s.listener.Close()
}

func (s *testServer) addr() string {
	return s.listener.Addr().String()
}

func TestCertChecker(t *testing.T) {
	now := time.Now()
	domain := "test.example.com"

	tests := []struct {
		name          string
		notBefore     time.Time
		notAfter      time.Time
		expectedDays  float64
		expectError   bool
		errorContains string
	}{
		{
			name:         "valid certificate - 30 days remaining",
			notBefore:    now.Add(-24 * time.Hour),
			notAfter:     now.Add(30 * 24 * time.Hour),
			expectedDays: 30,
		},
		{
			name:         "near expiration - 7 days remaining",
			notBefore:    now.Add(-24 * time.Hour),
			notAfter:     now.Add(7 * 24 * time.Hour),
			expectedDays: 7,
		},
		{
			name:         "expired certificate",
			notBefore:    now.Add(-48 * time.Hour),
			notAfter:     now.Add(-24 * time.Hour),
			expectedDays: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, err := newTestServer(t, domain, tt.notBefore, tt.notAfter)
			if err != nil {
				t.Fatalf("Failed to create test server: %v", err)
			}
			defer server.close()

			host, port, err := net.SplitHostPort(server.addr())
			if err != nil {
				t.Fatalf("Failed to split host/port: %v", err)
			}

			checker := NewCertChecker(host, port)
			expireDate, certDomain, err := checker.Check()

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got nil")
				} else if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error containing %q but got %q", tt.errorContains, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if certDomain != domain {
				t.Errorf("Expected domain %q but got %q", domain, certDomain)
			}

			days := calculateDaysRemaining(*expireDate)
			// Allow for small timing differences
			if days < tt.expectedDays-1 || days > tt.expectedDays+1 {
				t.Errorf("Expected approximately %.0f days, got %.0f", tt.expectedDays, days)
			}
		})
	}
}

func TestCalculateDaysRemaining(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name       string
		expireDate time.Time
		want       float64
	}{
		{
			name:       "30 days remaining",
			expireDate: now.Add(30 * 24 * time.Hour),
			want:       30,
		},
		{
			name:       "7 days remaining",
			expireDate: now.Add(7 * 24 * time.Hour),
			want:       7,
		},
		{
			name:       "1 day remaining",
			expireDate: now.Add(24 * time.Hour),
			want:       1,
		},
		{
			name:       "expired 1 day ago",
			expireDate: now.Add(-24 * time.Hour),
			want:       -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := calculateDaysRemaining(tt.expireDate)
			if got < tt.want-0.1 || got > tt.want+0.1 {
				t.Errorf("calculateDaysRemaining() = %v, want %v", got, tt.want)
			}
		})
	}
}
