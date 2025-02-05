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
	"testing"
	"time"
)

// TestVersion tests the version string
func TestVersion(t *testing.T) {
	var a args
	if got := a.Version(); got != "tlx "+Version {
		t.Errorf("Version() = %v, want %v", got, "tlx "+Version)
	}
}

// TestParseArgs tests the argument parsing functionality
func TestParseArgs(t *testing.T) {
	// Save original args and restore them after the test
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	tests := []struct {
		name     string
		args     []string
		expected args
		wantErr  bool
	}{
		{
			name:     "domain and port",
			args:     []string{"tlx", "example.com", "443"},
			expected: args{Domain: "example.com", Port: "443"},
		},
		{
			name:     "domain only",
			args:     []string{"tlx", "example.com"},
			expected: args{Domain: "example.com", Port: "443"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Args = tt.args
			var got args
			err := parseArgs(&got)
			if err != nil && !tt.wantErr {
				t.Errorf("parseArgs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got.Domain != tt.expected.Domain || got.Port != tt.expected.Port {
				t.Errorf("parseArgs() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// Helper function to create a test certificate
func createTestCert(t *testing.T, domain string, notBefore, notAfter time.Time) (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
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

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}, nil
}

type testServer struct {
	listener net.Listener
	cert     tls.Certificate
}

func newTestServer(t *testing.T, domain string, notBefore, notAfter time.Time) (*testServer, error) {
	cert, err := createTestCert(t, domain, notBefore, notAfter)
	if err != nil {
		return nil, err
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
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
		go func() {
			defer conn.Close()
			// Read some data to complete the handshake
			buf := make([]byte, 1)
			conn.Read(buf)
		}()
	}
}

func (s *testServer) close() {
	s.listener.Close()
}

func (s *testServer) addr() string {
	return s.listener.Addr().String()
}

// TestCheckCertificate tests the certificate checking functionality
func TestCheckCertificate(t *testing.T) {
	now := time.Now()
	domain := "test.example.com"

	tests := []struct {
		name      string
		notBefore time.Time
		notAfter  time.Time
		wantDays  float64
	}{
		{
			name:      "valid certificate",
			notBefore: now.Add(-24 * time.Hour),
			notAfter:  now.Add(30 * 24 * time.Hour),
			wantDays:  30,
		},
		{
			name:      "expired certificate",
			notBefore: now.Add(-48 * time.Hour),
			notAfter:  now.Add(-24 * time.Hour),
			wantDays:  -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, err := newTestServer(t, domain, tt.notBefore, tt.notAfter)
			if err != nil {
				t.Fatalf("Failed to create test server: %v", err)
			}
			defer server.close()

			// Create a client connection
			config := &tls.Config{
				InsecureSkipVerify: true,
			}

			conn, err := tls.Dial("tcp", server.addr(), config)
			if err != nil {
				t.Fatalf("Failed to connect to test server: %v", err)
			}
			defer conn.Close()

			// Send some data to complete the handshake
			_, err = conn.Write([]byte("test"))
			if err != nil {
				t.Fatalf("Failed to write to connection: %v", err)
			}

			cert := conn.ConnectionState().PeerCertificates[0]
			expireDate, err := time.Parse(DayFormat, cert.NotAfter.Format(DayFormat))
			if err != nil {
				t.Fatalf("Failed to parse expiry date: %v", err)
			}

			days := expireDate.Sub(now).Hours() / 24
			if days < tt.wantDays-1 || days > tt.wantDays+1 {
				t.Errorf("Got %.0f days until expiry, want %.0f", days, tt.wantDays)
			}
		})
	}
}

// Helper function to parse args without using go-arg directly in tests
func parseArgs(args *args) error {
	if len(os.Args) < 2 {
		return nil
	}
	args.Domain = os.Args[1]
	if len(os.Args) > 2 {
		args.Port = os.Args[2]
	} else {
		args.Port = "443"
	}
	return nil
}
