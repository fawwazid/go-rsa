package gorsa

import "errors"

var (
	// ErrNilPrivateKey is returned when a private key is expected but nil is provided.
	ErrNilPrivateKey = errors.New("private key cannot be nil")

	// ErrNilPublicKey is returned when a public key is expected but nil is provided.
	ErrNilPublicKey = errors.New("public key cannot be nil")

	// ErrKeySizeTooSmall is returned when an RSA key is smaller than 2048 bits.
	ErrKeySizeTooSmall = errors.New("RSA key must be at least 2048 bits")

	// ErrInvalidPEM is returned when the PEM block cannot be parsed.
	ErrInvalidPEM = errors.New("failed to parse PEM block containing the key")

	// ErrNotRSAKey is returned when the key type is not RSA.
	ErrNotRSAKey = errors.New("key type is not RSA")
)
