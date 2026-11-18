package stack

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// ca is a throwaway CA and the one leaf it signed, for 127.0.0.1, generated per stack.
type ca struct {
	// file holds the CA certificate as PEM, for the app instances' -idp-ca.
	file string
	// certFile and keyFile hold the leaf, for Dex.
	certFile, keyFile string
	pool              *x509.CertPool
	leaf              tls.Certificate
	// spki is the base64 SHA-256 of the leaf's public key, which Chromium's
	// --ignore-certificate-errors-spki-list takes: it trusts exactly this key, and not every bad
	// certificate as --ignore-certificate-errors would.
	spki string
}

func newCA(dir string) (*ca, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "auth example throwaway CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		return nil, err
	}

	c := &ca{
		file:     filepath.Join(dir, "ca.pem"),
		certFile: filepath.Join(dir, "leaf.pem"),
		keyFile:  filepath.Join(dir, "leaf-key.pem"),
		pool:     x509.NewCertPool(),
		leaf:     tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey, Leaf: leafCert},
	}
	c.pool.AddCert(caCert)
	sum := sha256.Sum256(leafCert.RawSubjectPublicKeyInfo)
	c.spki = base64.StdEncoding.EncodeToString(sum[:])
	for _, f := range []struct {
		path, typ string
		der       []byte
	}{
		{c.file, "CERTIFICATE", caDER},
		{c.certFile, "CERTIFICATE", leafDER},
		{c.keyFile, "EC PRIVATE KEY", keyDER},
	} {
		if err := os.WriteFile(f.path, pem.EncodeToMemory(&pem.Block{Type: f.typ, Bytes: f.der}), 0o600); err != nil {
			return nil, err
		}
	}
	return c, nil
}
