package gorsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// GenerateKeys generates a new RSA key pair of the given bit size.
//
// The bit size must be at least 2048 to comply with NIST standards.
//
// Returns the private key, public key, or an error if generation fails or the bit size is too small.
func GenerateKeys(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	if bits < 2048 {
		return nil, nil, errors.New("key size must be at least 2048 bits")
	}
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	return priv, &priv.PublicKey, nil
}

// PrivateKeyToPEM converts an RSA private key to PEM format.
//
// It marshals the private key to PKCS#1 ASN.1 DER syntax and encodes it to a PEM block.
//
// Returns the PEM-encoded private key as a byte slice.
func PrivateKeyToPEM(priv *rsa.PrivateKey) []byte {
	privBytes := x509.MarshalPKCS1PrivateKey(priv)
	privPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privBytes,
		},
	)
	return privPEM
}

// PublicKeyToPEM converts an RSA public key to PEM format.
//
// It marshals the public key to PKIX ASN.1 DER syntax and encodes it to a PEM block.
//
// Returns the PEM-encoded public key as a byte slice, or an error if marshaling fails.
func PublicKeyToPEM(pub *rsa.PublicKey) ([]byte, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	pubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubBytes,
		},
	)
	return pubPEM, nil
}

// ParsePrivateKeyFromPEM parses an RSA private key from PEM format.
//
// It decodes the PEM block and parses the PKCS#1 private key.
// Note: Only the first PEM block is parsed; any additional blocks or trailing data are ignored.
//
// Returns the parsed private key or an error if parsing fails.
func ParsePrivateKeyFromPEM(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return priv, nil
}

// ParsePublicKeyFromPEM parses an RSA public key from PEM format.
//
// It decodes the PEM block and parses the PKIX public key.
// Note: Only the first PEM block is parsed; any additional blocks or trailing data are ignored.
//
// Returns the parsed public key or an error if parsing fails or the key is not an RSA key.
func ParsePublicKeyFromPEM(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		return nil, errors.New("key type is not RSA")
	}
}
