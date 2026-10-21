package main

import (
	"os"
	"testing"
	"time"

	"github.com/alecthomas/kong"
)

func TestCLIParsesTLSOptionsWithUpstreamFlags(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		env  map[string]string
		ca   string
		cert string
		key  string
	}{
		{
			name: "default-filenames",
			args: []string{"--ttl=30s", "--feature-gates=CELHealthcheckCustomizations=false"},
			ca:   "ca.crt", cert: "tls.crt", key: "tls.key",
		},
		{
			name: "filename-flags",
			args: []string{"--ttl=30s", "--feature-gates=CELHealthcheckCustomizations=false", "--tlsca-cert-file-name=client/ca.pem", "--tls-cert-file-name=server/cert.pem", "--tls-key-file-name=server/key.pem"},
			ca:   "client/ca.pem", cert: "server/cert.pem", key: "server/key.pem",
		},
		{
			name: "emissary-environment",
			args: []string{"--ttl=30s", "--feature-gates=CELHealthcheckCustomizations=false"},
			env: map[string]string{
				"TLS_SERVER_CERTS_DIR": "/etc/emissary/certs",
				"TLS_CA_CERT_FILENAME": "client/ca.pem",
				"TLS_CERT_FILENAME":    "server/cert.pem",
				"TLS_KEY_FILENAME":     "server/key.pem",
			},
			ca: "client/ca.pem", cert: "server/cert.pem", key: "server/key.pem",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, name := range []string{"TLS_SERVER_CERTS_DIR", "TLS_CA_CERT_FILENAME", "TLS_CERT_FILENAME", "TLS_KEY_FILENAME"} {
				t.Setenv(name, tc.env[name])
				if _, exists := tc.env[name]; !exists {
					if err := os.Unsetenv(name); err != nil {
						t.Fatal(err)
					}
				}
			}
			cli := &CLI{}
			parser, err := kong.New(cli)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parser.Parse(tc.args); err != nil {
				t.Fatalf("parse TLS configuration alongside upstream TTL and feature-gate flags: %v", err)
			}
			if cli.TTL == nil || *cli.TTL != 30*time.Second {
				t.Errorf("TTL = %v, want 30s", cli.TTL)
			}
			if cli.FeatureGates != "CELHealthcheckCustomizations=false" {
				t.Errorf("feature gates = %q, want CELHealthcheckCustomizations=false", cli.FeatureGates)
			}
			if cli.TLSCACertFileName != tc.ca || cli.TLSCertFileName != tc.cert || cli.TLSKeyFileName != tc.key {
				t.Errorf("TLS filenames = (%q, %q, %q), want (%q, %q, %q)", cli.TLSCACertFileName, cli.TLSCertFileName, cli.TLSKeyFileName, tc.ca, tc.cert, tc.key)
			}
			if cli.TLSCertsDir != tc.env["TLS_SERVER_CERTS_DIR"] {
				t.Errorf("TLS directory = %q, want %q", cli.TLSCertsDir, tc.env["TLS_SERVER_CERTS_DIR"])
			}
		})
	}
}
