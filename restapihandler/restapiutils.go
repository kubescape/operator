package restapihandler

import (
	"crypto/tls"
	"flag"
	"fmt"
)

func (handler *HTTPHandler) loadTLSKey() error {
	certFile := ""
	keyFile := ""

	flag.StringVar(&certFile, "tlsCertFile", "", "File containing the x509 Certificate for HTTPS.")
	flag.StringVar(&keyFile, "tlsKeyFile", "", "File containing the x509 private key to --tlsCertFile.")
	// flag.BoolVar(&localAgent, "debug", false, "Run with local agent")
	flag.Parse()

	if keyFile == "" || certFile == "" {
		return nil
	}

	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("Filed to load key pair: %v", err)
	}
	handler.keyPair = &pair
	return nil
}
