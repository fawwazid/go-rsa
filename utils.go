package gorsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

// GenerateKeys generates a new RSA key pair of the given bit size.
//
// The bit size must be at least 2048 to comply with NIST standards.
//
// Returns the private key, public key, or an error if generation fails or the bit size is too small.
func GenerateKeys(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	if bits < 2048 {
		return nil, nil, ErrKeySizeTooSmall
	}
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	return priv, &priv.PublicKey, nil
}

func validatePublicKey(pub *rsa.PublicKey) error {
	if pub == nil {
		return ErrNilPublicKey
	}
	if pub.N == nil || pub.N.BitLen() < 2048 {
		return ErrKeySizeTooSmall
	}
	return nil
}

func validatePrivateKey(priv *rsa.PrivateKey) error {
	if priv == nil {
		return ErrNilPrivateKey
	}
	if priv.N == nil || priv.N.BitLen() < 2048 {
		return ErrKeySizeTooSmall
	}
	return nil
}

// PrivateKeyToPEM converts an RSA private key to PEM format.
//
// It marshals the private key to PKCS#1 ASN.1 DER syntax and encodes it to a PEM block.
//
// Returns the PEM-encoded private key as a byte slice, or an error if the key is nil or too small.
func PrivateKeyToPEM(priv *rsa.PrivateKey) ([]byte, error) {
	if err := validatePrivateKey(priv); err != nil {
		return nil, err
	}
	privBytes := x509.MarshalPKCS1PrivateKey(priv)
	privPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privBytes,
		},
	)
	return privPEM, nil
}

// PublicKeyToPEM converts an RSA public key to PEM format.
//
// It marshals the public key to PKIX ASN.1 DER syntax and encodes it to a PEM block.
//
// Returns the PEM-encoded public key as a byte slice, or an error if the key is nil, too small, or marshaling fails.
func PublicKeyToPEM(pub *rsa.PublicKey) ([]byte, error) {
	if err := validatePublicKey(pub); err != nil {
		return nil, err
	}
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
// Returns the parsed private key or an error if parsing fails or the key is smaller than 2048 bits.
func ParsePrivateKeyFromPEM(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, ErrInvalidPEM
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	if err := validatePrivateKey(priv); err != nil {
		return nil, err
	}

	return priv, nil
}

// ParsePublicKeyFromPEM parses an RSA public key from PEM format.
//
// It decodes the PEM block and parses the PKIX public key.
// Note: Only the first PEM block is parsed; any additional blocks or trailing data are ignored.
//
// Returns the parsed public key or an error if parsing fails, the key is not an RSA key,
// or the key is smaller than 2048 bits.
func ParsePublicKeyFromPEM(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, ErrInvalidPEM
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		if err := validatePublicKey(pub); err != nil {
			return nil, err
		}
		return pub, nil
	default:
		return nil, ErrNotRSAKey
	}
}
