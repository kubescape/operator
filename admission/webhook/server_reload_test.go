package webhook

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/admission"
)

// writeSelfSignedCert writes a self-signed certificate (identified by serial) and
// its key to certPath/keyPath and bumps their mtimes so that a rewrite is always
// visible to metadata checks, whatever the filesystem's timestamp resolution.
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
	conn, err := dialReloadTest(addr, "")
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

// End to end: rotate the certificate files while the webhook is serving, expect
// the new certificate to be served on the same address, and expect Run to return
// promptly once its context is cancelled afterwards.
func TestRun_ReloadsRotatedCertificate(t *testing.T) {
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
	requireRotatedSerial(t, addr, 2, "")

	// A second rotation must work as well on the same server.
	writeSelfSignedCert(t, certPath, keyPath, 3)
	requireRotatedSerial(t, addr, 3, "")

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

// writeCertOnly replaces just the certificate with one that belongs to a different key, the
// way a rotation looks while the new key has not been written yet.
func writeCertOnly(t *testing.T, certPath string, serial int64) {
	t.Helper()
	other := t.TempDir()
	writeSelfSignedCert(t, filepath.Join(other, "tls.crt"), filepath.Join(other, "tls.key"), serial)
	certPEM, err := os.ReadFile(filepath.Join(other, "tls.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	mtime := time.Now().Add(time.Duration(serial) * time.Minute)
	if err := os.Chtimes(certPath, mtime, mtime); err != nil {
		t.Fatal(err)
	}
}

// requireStillServing checks, for the given duration, that addr keeps serving the certificate
// with the given serial and that Run has not returned.
func requireStillServing(t *testing.T, addr string, serial int64, done <-chan error, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			t.Fatalf("Run returned %v while the replacement was invalid", err)
		default:
		}
		got, err := servedSerial(addr)
		if err != nil {
			t.Fatalf("server stopped serving while the replacement was invalid: %v", err)
		}
		if got != serial {
			t.Fatalf("served certificate #%d, want #%d", got, serial)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// A rotation can be seen half done: a new certificate next to the old key, a key that is
// missing, a truncated certificate. The server must keep serving the last good pair, Run must
// not return, and the next valid pair must be picked up.
func TestRun_KeepsServingWhenReplacementIsInvalid(t *testing.T) {
	cases := map[string]func(t *testing.T, certPath, keyPath string){
		"certificate without its key": func(t *testing.T, certPath, keyPath string) {
			writeCertOnly(t, certPath, 2)
		},
		"missing certificate": func(t *testing.T, certPath, keyPath string) {
			if err := os.Remove(certPath); err != nil {
				t.Fatal(err)
			}
		},
		"malformed key": func(t *testing.T, certPath, keyPath string) {
			if err := os.WriteFile(keyPath, []byte("not a key"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"missing key": func(t *testing.T, certPath, keyPath string) {
			if err := os.Remove(keyPath); err != nil {
				t.Fatal(err)
			}
		},
		"malformed certificate": func(t *testing.T, certPath, keyPath string) {
			if err := os.WriteFile(certPath, []byte("not a certificate"), 0o600); err != nil {
				t.Fatal(err)
			}
			later := time.Now().Add(2 * time.Minute)
			if err := os.Chtimes(certPath, later, later); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, invalidate := range cases {
		t.Run(name, func(t *testing.T) {
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

			invalidate(t, certPath, keyPath)
			requireStillServing(t, addr, 1, done, 400*time.Millisecond)

			writeSelfSignedCert(t, certPath, keyPath, 3)
			requireRotatedSerial(t, addr, 3, "")

			cancel()
			select {
			case err := <-done:
				if err != nil && err != context.Canceled {
					t.Fatalf("Run returned %v, want context.Canceled", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("Run did not return after its context was cancelled")
			}
		})
	}
}

// startReloadTestWebhook waits only for initial readiness. Once it returns,
// connection errors must not be hidden by retries in continuity checks.
func startReloadTestWebhook(t *testing.T, wh *webhook) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- wh.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Errorf("Run returned %v, want context.Canceled", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Run did not stop after cancellation")
		}
	})
	waitForSerial(t, wh.addr, 1, 5*time.Second)
}

func dialReloadTest(addr, serverName string) (*tls.Conn, error) {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true, ServerName: serverName, // Test certificates are self-signed.
		ClientSessionCache: nil,
	})
	if err != nil {
		return nil, err
	}
	if conn.ConnectionState().DidResume {
		_ = conn.Close()
		return nil, errors.New("unexpected resumed TLS connection")
	}
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func healthRoundTrip(conn *tls.Conn, reader *bufio.Reader) error {
	req, err := http.NewRequest(http.MethodGet, "https://localhost/health", nil)
	if err != nil {
		return err
	}
	if err := req.Write(conn); err != nil {
		return err
	}
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK || string(body) != "OK" {
		return fmt.Errorf("health response: %s %q", resp.Status, body)
	}
	return nil
}

func TestRun_ExistingConnectionSurvivesRotation(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	writeSelfSignedCert(t, certPath, keyPath, 1)
	wh := &webhook{addr: freeLoopbackAddr(t), certFile: certPath, keyFile: keyPath}
	startReloadTestWebhook(t, wh)
	conn, err := dialReloadTest(wh.addr, "")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	reader := bufio.NewReader(conn)
	if err := healthRoundTrip(conn, reader); err != nil {
		t.Fatal(err)
	}
	writeSelfSignedCert(t, certPath, keyPath, 2)
	requireRotatedSerial(t, wh.addr, 2, "")
	// This is the original raw connection; no transport can reconnect for us.
	if err := healthRoundTrip(conn, reader); err != nil {
		t.Fatalf("existing connection interrupted by rotation: %v", err)
	}
}

type heldReloadValidator struct {
	MockValidator
	entered chan struct{}
	release chan struct{}
}

func (v *heldReloadValidator) Validate(context.Context, admission.Attributes, admission.ObjectInterfaces) error {
	close(v.entered)
	<-v.release
	return nil
}

func TestRun_ConcurrentConnectionsSurviveRotation(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	writeSelfSignedCert(t, certPath, keyPath, 1)
	validator := &heldReloadValidator{entered: make(chan struct{}), release: make(chan struct{})}
	wh := New(freeLoopbackAddr(t), certPath, keyPath, runtime.NewScheme(), validator, nil).(*webhook)
	startReloadTestWebhook(t, wh)
	held, err := dialReloadTest(wh.addr, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Close() }()
	var release sync.Once
	defer release.Do(func() { close(validator.release) })
	req, err := http.NewRequest(http.MethodPost, "https://localhost/validate", strings.NewReader(`{"request":{"uid":"rotation","operation":"CREATE"}}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if err := req.Write(held); err != nil {
		t.Fatal(err)
	}
	select {
	case <-validator.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("admission request did not enter validator")
	}

	const workers = 8
	failures := make(chan error, workers)
	ready := make(chan struct{}, workers)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var stopOnce sync.Once
	stopWorkers := func() { stopOnce.Do(func() { close(stop) }); wg.Wait() }
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			first := true
			for {
				select {
				case <-stop:
					return
				default:
				}
				conn, err := dialReloadTest(wh.addr, "localhost")
				if err == nil {
					err = healthRoundTrip(conn, bufio.NewReader(conn))
					_ = conn.Close()
				}
				if first {
					ready <- struct{}{}
					first = false
				}
				if err != nil {
					failures <- err
					return
				}
			}
		}()
	}
	defer stopWorkers()
	for i := 0; i < workers; i++ {
		<-ready
	}
	for serial := int64(2); serial <= 4; serial++ {
		writeSelfSignedCert(t, certPath, keyPath, serial)
		requireRotatedSerial(t, wh.addr, serial, "localhost")
	}
	release.Do(func() { close(validator.release) })
	resp, err := http.ReadResponse(bufio.NewReader(held), req)
	if err != nil {
		t.Fatalf("in-flight admission request interrupted: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"uid":"rotation"`) {
		t.Fatalf("admission response: %s %s, %v", resp.Status, body, err)
	}
	// Stop and join before inspecting errors from every worker.
	stopWorkers()
	close(failures)
	for err := range failures {
		t.Errorf("fresh HTTPS request failed during rotation: %v", err)
	}
}

// Unlike readiness polling, a rotation check must not mask transport failures.
func requireRotatedSerial(t *testing.T, addr string, serial int64, serverName string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := dialReloadTest(addr, serverName)
		if err != nil {
			t.Fatalf("TLS connection failed during rotation: %v", err)
		}
		got := conn.ConnectionState().PeerCertificates[0].SerialNumber.Int64()
		err = healthRoundTrip(conn, bufio.NewReader(conn))
		_ = conn.Close()
		if err != nil {
			t.Fatalf("HTTPS request failed during rotation: %v", err)
		}
		if got == serial {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("certificate #%d was not served", serial)
}

func certificateSerial(t *testing.T, cert *tls.Certificate) int64 {
	t.Helper()
	if cert == nil {
		t.Fatal("nil certificate")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf.SerialNumber.Int64()
}

func TestCertificateCache_UnchangedFilesAvoidReload(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	writeSelfSignedCert(t, certPath, keyPath, 1)
	loads := 0
	cache, err := newCertificateCache(certPath, keyPath, func(cert, key string) (tls.Certificate, error) {
		loads++
		return tls.LoadX509KeyPair(cert, key)
	})
	if err != nil {
		t.Fatal(err)
	}
	original, err := cache.getCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		got, err := cache.getCertificate(nil)
		if err != nil || got != original {
			t.Fatalf("unchanged lookup: %p, %v; want %p, nil", got, err, original)
		}
	}
	if loads != 1 {
		t.Fatalf("loaded unchanged files %d times, want 1", loads)
	}
	writeSelfSignedCert(t, certPath, keyPath, 2)
	rotated, err := cache.getCertificate(nil)
	if err != nil || certificateSerial(t, rotated) != 2 {
		t.Fatalf("rotation failed: %v", err)
	}
	if loads != 2 {
		t.Fatalf("loaded files %d times, want 2", loads)
	}
	if certificateSerial(t, original) != 1 {
		t.Fatal("published certificate was mutated")
	}
}

func TestCertificateCache_RejectsUnstableStartupSnapshot(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	writeSelfSignedCert(t, certPath, keyPath, 1)
	calls := 0
	cache, err := newCertificateCache(certPath, keyPath, func(cert, key string) (tls.Certificate, error) {
		calls++
		pair, err := tls.LoadX509KeyPair(cert, key)
		// Deterministically rotate after the read but before metadata is recorded.
		writeSelfSignedCert(t, certPath, keyPath, 2)
		return pair, err
	})
	if err == nil || cache != nil {
		t.Fatal("accepted an unstable startup snapshot")
	}
	if calls != 1 {
		t.Fatalf("startup attempted %d loads, want one bounded attempt", calls)
	}
	cache, err = newCertificateCache(certPath, keyPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := cache.getCertificate(nil)
	if err != nil || certificateSerial(t, cert) != 2 {
		t.Fatalf("stable startup failed: %v", err)
	}
}

func TestCertificateCache_RejectsUnstableReloadSnapshot(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	writeSelfSignedCert(t, certPath, keyPath, 1)
	calls := 0
	cache, err := newCertificateCache(certPath, keyPath, func(cert, key string) (tls.Certificate, error) {
		calls++
		pair, err := tls.LoadX509KeyPair(cert, key)
		if calls == 2 {
			writeSelfSignedCert(t, certPath, keyPath, 3)
		}
		return pair, err
	})
	if err != nil {
		t.Fatal(err)
	}
	original, snapshot := cache.certificate, cache.snapshot
	writeSelfSignedCert(t, certPath, keyPath, 2)
	got, err := cache.getCertificate(nil)
	if err != nil || got != original || !snapshot.equal(cache.snapshot) {
		t.Fatalf("unstable reload changed successful cache state: %v", err)
	}
	if calls != 2 {
		t.Fatalf("reload attempted %d additional loads, want 1", calls-1)
	}
	got, err = cache.getCertificate(nil)
	if err != nil || certificateSerial(t, got) != 3 {
		t.Fatalf("stable retry failed: %v", err)
	}
}

func TestCertificateCache_RetriesFailedLoadWithoutMetadataChange(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	writeSelfSignedCert(t, certPath, keyPath, 1)
	calls := 0
	cache, err := newCertificateCache(certPath, keyPath, func(cert, key string) (tls.Certificate, error) {
		calls++
		if calls == 2 {
			return tls.Certificate{}, errors.New("temporary read failure")
		}
		return tls.LoadX509KeyPair(cert, key)
	})
	if err != nil {
		t.Fatal(err)
	}
	original, snapshot := cache.certificate, cache.snapshot
	writeSelfSignedCert(t, certPath, keyPath, 2)
	got, err := cache.getCertificate(nil)
	if err != nil || got != original || !snapshot.equal(cache.snapshot) {
		t.Fatalf("failed reload changed successful cache state: %v", err)
	}
	// No further filesystem change: the failed candidate must remain retryable.
	got, err = cache.getCertificate(nil)
	if err != nil || certificateSerial(t, got) != 2 || calls != 3 {
		t.Fatalf("retry failed: loads=%d, error=%v", calls, err)
	}
	if cache.lastWarning != "" {
		t.Fatal("successful retry did not reset warning state")
	}
}

func TestCertificateCache_ConcurrentReloadCannotPublishStaleCertificate(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	writeSelfSignedCert(t, certPath, keyPath, 1)
	loaded := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	calls := 0
	cache, err := newCertificateCache(certPath, keyPath, func(cert, key string) (tls.Certificate, error) {
		calls++
		pair, err := tls.LoadX509KeyPair(cert, key)
		if calls == 2 {
			close(loaded)
			<-release
		}
		return pair, err
	})
	if err != nil {
		t.Fatal(err)
	}
	writeSelfSignedCert(t, certPath, keyPath, 2)
	type result struct {
		cert *tls.Certificate
		err  error
	}
	older, newer := make(chan result, 1), make(chan result, 1)
	go func() { cert, err := cache.getCertificate(nil); older <- result{cert, err} }()
	select {
	case <-loaded:
	case <-time.After(3 * time.Second):
		t.Fatal("reload did not start")
	}
	writeSelfSignedCert(t, certPath, keyPath, 3)
	go func() { cert, err := cache.getCertificate(nil); newer <- result{cert, err} }()
	once.Do(func() { close(release) })
	for _, tc := range []struct {
		result <-chan result
		serial int64
	}{{older, 1}, {newer, 3}} {
		select {
		case got := <-tc.result:
			if got.err != nil || certificateSerial(t, got.cert) != tc.serial {
				t.Fatalf("concurrent callback: want serial %d, error %v", tc.serial, got.err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("concurrent reload did not finish")
		}
	}
	got, err := cache.getCertificate(nil)
	if err != nil || certificateSerial(t, got) != 3 {
		t.Fatalf("final certificate is stale: %v", err)
	}
}

func TestRun_ReloadsSecretSymlinkSwap(t *testing.T) {
	dir := t.TempDir()
	fixedTime := time.Unix(1700000000, 0)
	for i := 1; i <= 2; i++ {
		generation := filepath.Join(dir, fmt.Sprintf("generation%d", i))
		if err := os.Mkdir(generation, 0o700); err != nil {
			t.Fatal(err)
		}
		certPath, keyPath := filepath.Join(generation, "tls.crt"), filepath.Join(generation, "tls.key")
		writeSelfSignedCert(t, certPath, keyPath, int64(i))
		for _, path := range []string{certPath, keyPath} {
			contents, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			// PEM tolerates trailing whitespace. Both generations have identical
			// sizes and timestamps, leaving file identity as the only change signal.
			if len(contents) > 2048 {
				t.Fatal("test PEM exceeds padding size")
			}
			contents = append(contents, bytes.Repeat([]byte("\n"), 2048-len(contents))...)
			if err := os.WriteFile(path, contents, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chtimes(path, fixedTime, fixedTime); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, name := range []string{"tls.crt", "tls.key"} {
		if err := os.Symlink(filepath.Join("..data", name), filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
		first, err := os.Stat(filepath.Join(dir, "generation1", name))
		if err != nil {
			t.Fatal(err)
		}
		second, err := os.Stat(filepath.Join(dir, "generation2", name))
		if err != nil {
			t.Fatal(err)
		}
		if first.Size() != second.Size() || !first.ModTime().Equal(second.ModTime()) || os.SameFile(first, second) {
			t.Fatal("test generations must differ only in identity")
		}
	}
	if err := os.Symlink("generation1", filepath.Join(dir, "..data")); err != nil {
		t.Fatal(err)
	}
	wh := &webhook{addr: freeLoopbackAddr(t), certFile: filepath.Join(dir, "tls.crt"), keyFile: filepath.Join(dir, "tls.key")}
	startReloadTestWebhook(t, wh)
	if err := os.Symlink("generation2", filepath.Join(dir, "..data_tmp")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "..data_tmp"), filepath.Join(dir, "..data")); err != nil {
		t.Fatal(err)
	}
	requireRotatedSerial(t, wh.addr, 2, "")
	requireRotatedSerial(t, wh.addr, 2, "localhost")
}

func TestRun_ReturnsStartupErrors(t *testing.T) {
	for _, invalid := range []string{"missing certificate", "missing key", "malformed certificate", "malformed key", "mismatched pair"} {
		t.Run(invalid, func(t *testing.T) {
			dir := t.TempDir()
			certPath, keyPath := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
			writeSelfSignedCert(t, certPath, keyPath, 1)
			switch invalid {
			case "missing certificate":
				if err := os.Remove(certPath); err != nil {
					t.Fatal(err)
				}
			case "missing key":
				if err := os.Remove(keyPath); err != nil {
					t.Fatal(err)
				}
			case "malformed certificate", "malformed key":
				path := certPath
				if invalid == "malformed key" {
					path = keyPath
				}
				if err := os.WriteFile(path, []byte("invalid PEM"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "mismatched pair":
				writeCertOnly(t, certPath, 2)
			}
			wh := &webhook{addr: freeLoopbackAddr(t), certFile: certPath, keyFile: keyPath}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			err := wh.Run(ctx)
			if err == nil || errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("Run returned %v, want startup certificate error", err)
			}
			conn, err := net.DialTimeout("tcp", wh.addr, time.Second)
			if err == nil {
				_ = conn.Close()
				t.Fatal("started listener with invalid initial pair")
			}
		})
	}
}

func TestRun_ReturnsListenError(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	writeSelfSignedCert(t, certPath, keyPath, 1)
	wh := &webhook{addr: listener.Addr().String(), certFile: certPath, keyFile: keyPath}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var listenErr *net.OpError
	if err := wh.Run(ctx); !errors.As(err, &listenErr) || listenErr.Op != "listen" {
		t.Fatalf("Run returned %v, want listen error", err)
	}
}
