package webhook

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// --- test PKI helpers -------------------------------------------------------

// testCA is a certificate authority usable to sign server and client certs and
// to emit its own PEM for use as a trusted client-CA bundle.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	der  []byte
}

func newTestCA(t *testing.T, cn string, serial int64) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: cert, key: key, der: der}
}

func (ca *testCA) pem() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.der})
}

// issue signs a leaf certificate for the given usage and returns a tls
// client/server certificate ready to present in a handshake.
func (ca *testCA) issue(t *testing.T, cn string, serial int64, eku x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{eku},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// writeServerCertFrom writes a server key pair signed by ca to certPath/keyPath.
func writeServerCertFrom(t *testing.T, ca *testCA, certPath, keyPath string, serial int64) {
	t.Helper()
	leaf := ca.issue(t, "localhost", serial, x509.ExtKeyUsageServerAuth)
	key := leaf.PrivateKey.(*ecdsa.PrivateKey)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Certificate[0]}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
}

// writeFileBumpMtime writes data and bumps mtime so metadata-based change
// detection sees the write regardless of filesystem timestamp resolution.
func writeFileBumpMtime(t *testing.T, path string, data []byte, minute int64) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	mt := time.Now().Add(time.Duration(minute) * time.Minute)
	if err := os.Chtimes(path, mt, mt); err != nil {
		t.Fatal(err)
	}
}

// dialWithClientCert performs a TLS handshake offering clientCert (nil for
// none) and, on success, runs a /health round trip. It returns the first error
// (handshake or request).
func dialWithClientCert(addr string, clientCert *tls.Certificate) error {
	cfg := &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"} // server cert trust is not under test here
	if clientCert != nil {
		cfg.Certificates = []tls.Certificate{*clientCert}
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", addr, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	return healthRoundTrip(conn, bufio.NewReader(conn))
}

// startClientAuthWebhook starts a webhook configured with clientCAFile and
// returns its address plus a stop func. It fails the test if Run returns an
// unexpected startup error.
func startClientAuthWebhook(t *testing.T, serverCA *testCA, clientCAFile string) (string, func()) {
	t.Helper()
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	writeServerCertFrom(t, serverCA, certPath, keyPath, 1)

	addr := freeLoopbackAddr(t)
	wh := &webhook{addr: addr, certFile: certPath, keyFile: keyPath, clientCAFile: clientCAFile, validator: &MockValidator{}}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- wh.Run(ctx) }()

	// Wait until the server accepts connections (any TLS error still proves the
	// listener is up; a dial refusal means it is not yet).
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not start: %v", err)
		}
		select {
		case err := <-done:
			t.Fatalf("Run returned during startup: %v", err)
		default:
		}
		time.Sleep(20 * time.Millisecond)
	}
	return addr, func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("Run did not return after cancel")
		}
	}
}

// --- tests ------------------------------------------------------------------

// Case 1 + 7: a client certificate signed by the trusted CA completes the
// handshake and is served (the legitimate API-server path).
func TestClientAuth_ValidClientCertAccepted(t *testing.T) {
	ca := newTestCA(t, "kubescape-admission-client-ca", 1)
	caFile := filepath.Join(t.TempDir(), "client-ca.crt")
	writeFileBumpMtime(t, caFile, ca.pem(), 1)

	addr, stop := startClientAuthWebhook(t, ca, caFile)
	defer stop()

	clientCert := ca.issue(t, "system:apiserver", 10, x509.ExtKeyUsageClientAuth)
	if err := dialWithClientCert(addr, &clientCert); err != nil {
		t.Fatalf("valid client cert was rejected: %v", err)
	}
}

// Case 2: no client certificate is rejected at the handshake.
func TestClientAuth_MissingClientCertRejected(t *testing.T) {
	ca := newTestCA(t, "kubescape-admission-client-ca", 1)
	caFile := filepath.Join(t.TempDir(), "client-ca.crt")
	writeFileBumpMtime(t, caFile, ca.pem(), 1)

	addr, stop := startClientAuthWebhook(t, ca, caFile)
	defer stop()

	if err := dialWithClientCert(addr, nil); err == nil {
		t.Fatal("handshake without a client certificate was accepted, want rejection")
	}
}

// Cases 3 + 4: a client certificate signed by an untrusted CA is rejected.
func TestClientAuth_UntrustedClientCertRejected(t *testing.T) {
	trusted := newTestCA(t, "trusted-ca", 1)
	untrusted := newTestCA(t, "untrusted-ca", 2)
	caFile := filepath.Join(t.TempDir(), "client-ca.crt")
	writeFileBumpMtime(t, caFile, trusted.pem(), 1)

	addr, stop := startClientAuthWebhook(t, trusted, caFile)
	defer stop()

	rogue := untrusted.issue(t, "attacker", 99, x509.ExtKeyUsageClientAuth)
	if err := dialWithClientCert(addr, &rogue); err == nil {
		t.Fatal("client cert from an untrusted CA was accepted, want rejection")
	}
}

// Case 5: rotating the client-CA file to a new CA causes certs from the new CA
// to be accepted and certs from the old CA to be rejected, without a restart.
func TestClientAuth_CARotation(t *testing.T) {
	oldCA := newTestCA(t, "old-ca", 1)
	newCA := newTestCA(t, "new-ca", 2)
	caFile := filepath.Join(t.TempDir(), "client-ca.crt")
	writeFileBumpMtime(t, caFile, oldCA.pem(), 1)

	// Server cert signed by oldCA; server identity is not under test (clients
	// skip server verification), so it need not rotate.
	addr, stop := startClientAuthWebhook(t, oldCA, caFile)
	defer stop()

	oldClient := oldCA.issue(t, "client", 10, x509.ExtKeyUsageClientAuth)
	newClient := newCA.issue(t, "client", 11, x509.ExtKeyUsageClientAuth)

	if err := dialWithClientCert(addr, &oldClient); err != nil {
		t.Fatalf("pre-rotation: old client cert rejected: %v", err)
	}
	if err := dialWithClientCert(addr, &newClient); err == nil {
		t.Fatal("pre-rotation: new client cert accepted before its CA was trusted")
	}

	// Rotate the trust bundle to the new CA.
	writeFileBumpMtime(t, caFile, newCA.pem(), 5)

	deadline := time.Now().Add(3 * time.Second)
	for {
		if err := dialWithClientCert(addr, &newClient); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("post-rotation: new client cert not accepted after CA rotation")
		}
		time.Sleep(25 * time.Millisecond)
	}
	if err := dialWithClientCert(addr, &oldClient); err == nil {
		t.Fatal("post-rotation: old client cert still accepted after CA rotation")
	}
}

// Case 6: misconfiguration fails safe. A configured-but-unloadable CA makes the
// constructor (and therefore Run) return an error rather than silently serving
// unauthenticated.
func TestClientAuth_MisconfiguredFailsSafe(t *testing.T) {
	t.Run("missing file", func(t *testing.T) {
		if _, err := newClientCACacheIfConfigured(filepath.Join(t.TempDir(), "does-not-exist.crt")); err == nil {
			t.Fatal("missing client CA file did not produce a startup error")
		}
	})
	t.Run("empty / non-certificate file", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "garbage.crt")
		if err := os.WriteFile(p, []byte("not a certificate"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := newClientCACacheIfConfigured(p); err == nil {
			t.Fatal("non-certificate client CA file did not produce a startup error")
		}
	})
	t.Run("Run returns the startup error", func(t *testing.T) {
		dir := t.TempDir()
		certPath, keyPath := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
		ca := newTestCA(t, "server-ca", 1)
		writeServerCertFrom(t, ca, certPath, keyPath, 1)
		wh := &webhook{
			addr:         freeLoopbackAddr(t),
			certFile:     certPath,
			keyFile:      keyPath,
			clientCAFile: filepath.Join(dir, "absent-ca.crt"),
			validator:    &MockValidator{},
		}
		if err := wh.Run(context.Background()); err == nil {
			t.Fatal("Run did not fail when client auth was enabled with an unloadable CA")
		}
	})
}

// Case 8: disabled client auth (empty clientCAFile) preserves existing
// behaviour — a plain client with no certificate is served.
func TestClientAuth_DisabledPreservesExistingBehaviour(t *testing.T) {
	ca := newTestCA(t, "server-ca", 1)
	addr, stop := startClientAuthWebhook(t, ca, "") // empty => disabled
	defer stop()

	if err := dialWithClientCert(addr, nil); err != nil {
		t.Fatalf("with client auth disabled, a no-cert client should be served: %v", err)
	}
}

// buildTLSConfig wires client verification only when a CA cache is present, and
// never weakens the server-certificate callback.
func TestBuildTLSConfig_ClientAuthOnlyWhenConfigured(t *testing.T) {
	getCert := func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return nil, nil }

	disabled := buildTLSConfig(getCert, nil)
	if disabled.GetConfigForClient != nil {
		t.Fatal("client auth should be off when no CA cache is configured")
	}
	if disabled.ClientAuth != tls.NoClientCert {
		t.Fatalf("disabled config ClientAuth = %v, want NoClientCert", disabled.ClientAuth)
	}
	if disabled.GetCertificate == nil {
		t.Fatal("server certificate callback must always be set")
	}

	ca := newTestCA(t, "ca", 1)
	caFile := filepath.Join(t.TempDir(), "ca.crt")
	writeFileBumpMtime(t, caFile, ca.pem(), 1)
	cache, err := newClientCACache(caFile, nil)
	if err != nil {
		t.Fatal(err)
	}
	enabled := buildTLSConfig(getCert, cache)
	if enabled.GetConfigForClient == nil {
		t.Fatal("client auth should be on when a CA cache is configured")
	}
	perConn, err := enabled.GetConfigForClient(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if perConn.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("per-connection ClientAuth = %v, want RequireAndVerifyClientCert", perConn.ClientAuth)
	}
	if perConn.ClientCAs == nil {
		t.Fatal("per-connection config must carry the trusted client CA pool")
	}
}

// A CA reload that briefly reads back invalid keeps the last good pool rather
// than dropping to an empty (trust-nothing) or nil pool.
func TestClientCACache_KeepsLastGoodPoolOnReloadError(t *testing.T) {
	ca := newTestCA(t, "ca", 1)
	caFile := filepath.Join(t.TempDir(), "ca.crt")
	writeFileBumpMtime(t, caFile, ca.pem(), 1)
	cache, err := newClientCACache(caFile, nil)
	if err != nil {
		t.Fatal(err)
	}
	good := cache.pool

	// Corrupt the file as a half-written rotation would.
	writeFileBumpMtime(t, caFile, []byte("garbage"), 5)
	cfgFn := cache.getConfigForClient(&tls.Config{})
	perConn, err := cfgFn(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("getConfigForClient returned error: %v", err)
	}
	if perConn.ClientCAs != good {
		t.Fatal("reload error did not preserve the last good trust pool")
	}
	if perConn.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatal("reload error must not relax client-cert enforcement")
	}
}
