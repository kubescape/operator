package webhook

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

// Client authentication for the admission webhook is OPT-IN and defaults to
// off. When a client CA file is configured the server requires and verifies a
// client certificate that chains to that CA (mutual TLS); when it is not, the
// server keeps its previous server-authentication-only behaviour.
//
// This is opt-in on purpose. The Kubernetes API server only presents a client
// certificate to a webhook when the cluster administrator configures the
// control plane's --admission-control-config-file (an AdmissionConfiguration
// with a kubeConfigFile for the webhook). A Helm chart cannot set that flag,
// and some managed control planes do not expose it, so enforcing mutual TLS by
// default would break the API-server -> webhook call path in supported
// environments. Enabling it is therefore paired with that control-plane
// configuration (see docs/admission-webhook-client-auth.md).
//
// When it IS enabled the mode fails safe: an unreadable or empty CA file is a
// startup error, not a silent downgrade to unauthenticated, and a CA rotation
// that briefly reads back as invalid keeps the last good trust pool rather than
// dropping client verification.

// clientCACache holds the trusted client-CA pool and reloads it from disk when
// the backing file changes, so CA rotation is picked up without a restart. It
// mirrors certificateSnapshot/certificateCache used for the server certificate:
// a Kubernetes Secret volume replaces its ..data symlink on rotation, which the
// stat-based snapshot detects.
type clientCACache struct {
	mu       sync.Mutex
	caFile   string
	readFile func(string) ([]byte, error)
	pool     *x509.CertPool
	// raw is the exact PEM the current pool was built from; an unchanged file
	// need not be reparsed and an equal re-read is not treated as a change.
	raw         []byte
	snapshot    certificateSnapshot
	lastWarning string
}

// newClientCACache builds the initial trust pool. It returns an error when the
// file cannot be read or contains no certificate: callers treat that as a fatal
// misconfiguration so the webhook never starts believing it authenticates
// callers when it does not.
func newClientCACache(caFile string, readFile func(string) ([]byte, error)) (*clientCACache, error) {
	if readFile == nil {
		readFile = os.ReadFile
	}
	c := &clientCACache{caFile: caFile, readFile: readFile}
	if err := c.reloadIfChanged(); err != nil {
		return nil, err
	}
	return c, nil
}

// statCAFile snapshots the CA file's identity for change detection. The
// certificate snapshot type compares both files; the CA cache tracks a single
// file, so both slots hold its FileInfo.
func (c *clientCACache) statCAFile() (certificateSnapshot, error) {
	info, err := os.Stat(c.caFile)
	if err != nil {
		return certificateSnapshot{}, err
	}
	return certificateSnapshot{cert: info, key: info}, nil
}

// parsePool builds a cert pool from PEM, rejecting PEM that yields no
// certificate so a truncated or non-certificate file cannot silently produce an
// empty (and therefore trust-nothing) pool.
func parsePool(pem []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("no valid certificate found in client CA file")
	}
	return pool, nil
}

// reloadIfChanged reloads the pool when the file's identity/size/mtime changed.
// Like the server-certificate cache it re-stats after reading and refuses a
// read torn by a concurrent write, and it never publishes an empty pool.
func (c *clientCACache) reloadIfChanged() error {
	before, err := c.statCAFile()
	if err != nil {
		return err
	}
	if c.pool != nil && c.snapshot.equal(before) {
		return nil
	}
	pem, err := c.readFile(c.caFile)
	if err != nil {
		return err
	}
	after, err := c.statCAFile()
	if err != nil {
		return err
	}
	if !before.equal(after) {
		return errors.New("client CA file changed while being read")
	}
	pool, err := parsePool(pem)
	if err != nil {
		return err
	}
	c.pool = pool
	c.raw = pem
	c.snapshot = after
	return nil
}

// getConfigForClient is the tls.Config.GetConfigForClient callback. It is
// invoked per handshake, so it is where rotation is observed. A reload failure
// keeps the last good pool: a half-written rotation must not turn client
// verification off or start rejecting the API server. The returned config
// always requires and verifies a client certificate.
func (c *clientCACache) getConfigForClient(base *tls.Config) func(*tls.ClientHelloInfo) (*tls.Config, error) {
	return func(*tls.ClientHelloInfo) (*tls.Config, error) {
		c.mu.Lock()
		defer c.mu.Unlock()

		if err := c.reloadIfChanged(); err != nil {
			if msg := err.Error(); msg != c.lastWarning {
				logger.L().Warning("admission webhook: client CA reload failed, keeping the current trust pool",
					helpers.Error(err))
				c.lastWarning = msg
			}
		} else {
			c.lastWarning = ""
		}

		cfg := base.Clone()
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
		cfg.ClientCAs = c.pool
		return cfg, nil
	}
}

// buildTLSConfig returns the server TLS config. getCertificate always provides
// the (rotating) server certificate. When clientCA is nil the server keeps its
// server-authentication-only behaviour; when it is set every handshake requires
// and verifies a client certificate against the rotating trust pool.
func buildTLSConfig(getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error), clientCA *clientCACache) *tls.Config {
	cfg := &tls.Config{GetCertificate: getCertificate}
	if clientCA != nil {
		cfg.GetConfigForClient = clientCA.getConfigForClient(cfg)
	}
	return cfg
}

// newClientCACacheIfConfigured builds the trust pool when a CA file is
// configured and returns nil (no error) when client authentication is
// disabled. A configured-but-unloadable CA is wrapped so the startup log names
// the mode that failed.
func newClientCACacheIfConfigured(caFile string) (*clientCACache, error) {
	if caFile == "" {
		return nil, nil
	}
	cache, err := newClientCACache(caFile, nil)
	if err != nil {
		return nil, fmt.Errorf("admission webhook client authentication is enabled but its CA could not be loaded: %w", err)
	}
	return cache, nil
}
