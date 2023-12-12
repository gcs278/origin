package certgen

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

// MarshalECDSAPrivateKeyToDERFormat converts the ECDSA key to a string
// representation (SEC 1, ASN.1 DER form) suitable for dropping into a
// route's TLS key stanza.
func MarshalECDSAPrivateKeyToDERFormat(key *ecdsa.PrivateKey) (string, error) {
	data, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("failed to marshal private key: %v", err)
	}

	buf := &bytes.Buffer{}

	if err := pem.Encode(buf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: data}); err != nil {
		return "", err
	}

	return buf.String(), nil
}

// MarshalRSAPrivateKeyToDERFormat converts the RSA key to a string
// representation (SEC 1, ASN.1 DER form) suitable for dropping into a
// route's TLS key stanza.
func MarshalRSAPrivateKeyToDERFormat(key *rsa.PrivateKey) (string, error) {
	data := x509.MarshalPKCS1PrivateKey(key)

	buf := &bytes.Buffer{}

	if err := pem.Encode(buf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: data}); err != nil {
		return "", err
	}

	return buf.String(), nil
}

// MarshalCertToPEMString encodes derBytes to a PEM format suitable
// for dropping into a route's TLS certificate stanza.
func MarshalCertToPEMString(derBytes []byte) (string, error) {
	buf := &bytes.Buffer{}

	if err := pem.Encode(buf, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return "", fmt.Errorf("failed to encode cert data: %v", err)
	}

	return buf.String(), nil
}

// GenerateECDSAKeyPair creates a certificate key pair with optional
// hosts using the ECDSA algorithm. Certificate is valid from notBefore
// and expires after notAfter. It returns the root certificate in
// DER format, the leaf certificate in DER format, the leaf key
// object, and any errors.
func GenerateECDSAKeyPair(notBefore, notAfter time.Time, hosts ...string) ([]byte, []byte, *ecdsa.PrivateKey, error) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate root ECDSA key: %v", err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate leaf ECDSA key: %v", err)
	}
	rootDerBytes, derBytes, err := generateCertificatePair(notBefore, notAfter, rootKey, &rootKey.PublicKey, &leafKey.PublicKey, hosts...)
	return rootDerBytes, derBytes, leafKey, err
}

// GenerateRSAKeyPair creates a certificate key pair with optional
// hosts using the RSA algorithm. Certificate is valid from notBefore
// and expires after notAfter. It returns the root certificate in
// DER format, the leaf certificate in DER format, the leaf key
// object, and any errors.
func GenerateRSAKeyPair(notBefore, notAfter time.Time, bits int, hosts ...string) ([]byte, []byte, *rsa.PrivateKey, error) {
	rootKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate root RSA key: %v", err)
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate leaf RSA key: %v", err)
	}
	rootDerBytes, derBytes, err := generateCertificatePair(notBefore, notAfter, rootKey, &rootKey.PublicKey, &leafKey.PublicKey, hosts...)
	return rootDerBytes, derBytes, leafKey, err
}

// generateCertificatePair returns a certificate pair in DER encoding
// given a root (parent) key and a leaf (child) key. The leaf certificate
// will be signed by the root key. Certificate is valid from notBefore and
// expires after notAfter. A default hash algorithm is selected, but
// is no less than SHA256.
func generateCertificatePair(notBefore, notAfter time.Time, rootKey, rootPublicKey, leafPublicKey any, hosts ...string) ([]byte, []byte, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %v", err)
	}

	rootTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Red Hat"},
			CommonName:   "Root CA",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	rootDerBytes, err := x509.CreateCertificate(rand.Reader, &rootTemplate, &rootTemplate, rootPublicKey, rootKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create root certificate: %v", err)
	}

	serialNumber, err = rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %v", err)
	}

	leafCertTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Red Hat"},
			CommonName:   "test_cert",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			leafCertTemplate.IPAddresses = append(leafCertTemplate.IPAddresses, ip)
		} else {
			leafCertTemplate.DNSNames = append(leafCertTemplate.DNSNames, h)
		}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &leafCertTemplate, &rootTemplate, leafPublicKey, rootKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create leaf certificate: %v", err)
	}

	return rootDerBytes, derBytes, nil
}
