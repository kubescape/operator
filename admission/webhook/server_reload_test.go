package webhook

import (
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

// fastWatch makes the TLS file watcher poll quickly for the duration of a test.
func fastWatch(t *testing.T) {
	t.Helper()
	orig := certWatchInterval
	certWatchInterval = 20 * time.Millisecond
	t.Cleanup(func() { certWatchInterval = orig })
}

// writeSelfSignedCert writes a self-signed certificate (identified by serial) and
// its key to certPath/keyPath and bumps their mtimes so that a rewrite is always
// visible to an mtime-based watcher, whatever the filesystem's timestamp resolution.
func writeSelfSignedCert(t *testing.T, certPath, keyPath string, serial int64) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	mtime := time.Now().Add(time.Duration(serial) * time.Minute)
	for _, p := range []string{certPath, keyPath} {
		if err := os.Chtimes(p, mtime, mtime); err != nil {
			t.Fatal(err)
		}
	}
}

func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

// servedSerial returns the serial number of the certificate addr currently serves.
func servedSerial(addr string) (int64, error) {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates[0].SerialNumber.Int64(), nil
}

// waitForSerial polls addr until it serves the certificate with the given serial.
func waitForSerial(t *testing.T, addr string, serial int64, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	var last int64
	var lastErr error
	for time.Now().Before(deadline) {
		last, lastErr = servedSerial(addr)
		if lastErr == nil && last == serial {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("server did not serve certificate #%d within %s (last serial %d, last error %v)", serial, within, last, lastErr)
}

func TestNotifyChanges_ReportsModifiedFile(t *testing.T) {
	fastWatch(t)
	path := filepath.Join(t.TempDir(), "tls.crt")
	if err := os.WriteFile(path, []byte("v1"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	changes := notifyChanges(ctx, path)

	select {
	case <-changes:
		t.Fatal("reported a change for a file that was not modified")
	case <-time.After(200 * time.Millisecond):
	}

	if err := os.WriteFile(path, []byte("v2"), 0o600); err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(time.Minute)
	if err := os.Chtimes(path, later, later); err != nil {
		t.Fatal(err)
	}

	select {
	case <-changes:
	case <-time.After(2 * time.Second):
		t.Fatal("modifying the file was never reported")
	}
}

func TestNotifyChanges_ReportsFileDisappearing(t *testing.T) {
	fastWatch(t)
	path := filepath.Join(t.TempDir(), "tls.key")
	if err := os.WriteFile(path, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	changes := notifyChanges(ctx, path)

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	select {
	case <-changes:
	case <-time.After(2 * time.Second):
		t.Fatal("removing the file was never reported")
	}
}

func TestNotifyChanges_ClosesChannelWhenContextCancelled(t *testing.T) {
	fastWatch(t)
	ctx, cancel := context.WithCancel(context.Background())
	changes := notifyChanges(ctx, filepath.Join(t.TempDir(), "missing"))
	cancel()

	select {
	case _, ok := <-changes:
		if ok {
			t.Fatal("received a change event instead of a closed channel")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("channel was not closed after the context was cancelled")
	}
}

// End to end: rotate the certificate files while the webhook is serving, expect
// the new certificate to be served on the same address, and expect Run to return
// promptly once its context is cancelled afterwards.
func TestRun_ReloadsRotatedCertificate(t *testing.T) {
	fastWatch(t)
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	writeSelfSignedCert(t, certPath, keyPath, 1)

	addr := freeLoopbackAddr(t)
	wh := &webhook{addr: addr, certFile: certPath, keyFile: keyPath}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- wh.Run(ctx) }()

	waitForSerial(t, addr, 1, 5*time.Second)

	writeSelfSignedCert(t, certPath, keyPath, 2)
	waitForSerial(t, addr, 2, 5*time.Second)

	// A second rotation must work as well: the restart path has to leave the
	// watcher and the new server in a usable state.
	writeSelfSignedCert(t, certPath, keyPath, 3)
	waitForSerial(t, addr, 3, 5*time.Second)

	cancel()
	select {
	case err := <-done:
		if err != nil && err != context.Canceled {
			t.Fatalf("Run returned %v, want context.Canceled", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after its context was cancelled")
	}
}
