package gorsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// GenerateKeys generates a new RSA key pair of the given bit size.
// The bit size must be at least 2048 to comply with NIST standards.
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
func PublicKeyToPEM(pub *rsa.PublicKey) ([]byte, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	pubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pubBytes,
		},
	)
	return pubPEM, nil
}

// ParsePrivateKeyFromPEM parses an RSA private key from PEM format.
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
