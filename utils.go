package gorsa

import (
	"bytes"
	"crypto/fips140"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// GenerateKeys generates an RSA key pair of at least 2048 bits.
func GenerateKeys(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	if bits < 2048 {
		return nil, nil, ErrKeySizeTooSmall
	}
	if fips140.Enabled() && bits%2 != 0 {
		return nil, nil, ErrInvalidKey
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
	if pub.N.Sign() <= 0 || pub.N.Bit(0) == 0 || pub.E < 3 || pub.E%2 == 0 || pub.E > 1<<31-1 {
		return ErrInvalidKey
	}
	if fips140.Enabled() && (pub.N.BitLen()%2 != 0 || pub.E != 65537) {
		return ErrInvalidKey
	}
	return nil
}

func validatePrivateKey(priv *rsa.PrivateKey) error {
	if priv == nil {
		return ErrNilPrivateKey
	}
	if err := validatePublicKey(&priv.PublicKey); err != nil {
		return err
	}
	if priv.D == nil || priv.D.Sign() <= 0 || len(priv.Primes) != 2 {
		return ErrInvalidKey
	}
	for _, prime := range priv.Primes {
		if prime == nil || prime.Sign() <= 0 || prime.BitLen() < 2 {
			return ErrInvalidKey
		}
	}
	if fips140.Enabled() && priv.Primes[0].BitLen() != priv.Primes[1].BitLen() {
		return ErrInvalidKey
	}
	if err := priv.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	return nil
}

// PrivateKeyToPEM validates and encodes an unencrypted PKCS#8 PRIVATE KEY block.
func PrivateKeyToPEM(priv *rsa.PrivateKey) ([]byte, error) {
	if err := validatePrivateKey(priv); err != nil {
		return nil, err
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	privPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: privBytes,
		},
	)
	return privPEM, nil
}

// PublicKeyToPEM validates and encodes a PKIX PUBLIC KEY block.
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

// ParsePrivateKeyFromPEM parses and validates a single PKCS#8 PRIVATE KEY block.
// PEM headers and trailing payloads are rejected.
func ParsePrivateKeyFromPEM(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, rest := pem.Decode(pemBytes)
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrInvalidPEM
	}

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, ErrNotRSAKey
	}

	if err := validatePrivateKey(priv); err != nil {
		return nil, err
	}

	return priv, nil
}

// ParsePublicKeyFromPEM parses and validates a single PKIX PUBLIC KEY block.
// PEM headers and trailing payloads are rejected.
func ParsePublicKeyFromPEM(pemBytes []byte) (*rsa.PublicKey, error) {
	block, rest := pem.Decode(pemBytes)
	if block == nil || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
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
