package gorsa

import "errors"

var (
	// ErrInvalidKey is returned for structurally invalid RSA keys.
	ErrInvalidKey = errors.New("invalid RSA key")
	// ErrNilPrivateKey is returned when a private key is expected but nil is provided.
	ErrNilPrivateKey = errors.New("private key cannot be nil")

	// ErrNilPublicKey is returned when a public key is expected but nil is provided.
	ErrNilPublicKey = errors.New("public key cannot be nil")

	// ErrKeySizeTooSmall is returned when an RSA key is smaller than 2048 bits.
	ErrKeySizeTooSmall = errors.New("RSA key must be at least 2048 bits")
	// ErrKeySizeTooLarge is returned when an RSA key exceeds the resource limit.
	ErrKeySizeTooLarge = errors.New("RSA key must not exceed 8192 bits")

	// ErrInvalidPEM is returned when the PEM block cannot be parsed.
	ErrInvalidPEM = errors.New("failed to parse PEM block containing the key")
	// ErrMessageTooLong is returned when a message is too large for RSA-OAEP.
	ErrMessageTooLong = errors.New("message is too long for RSA-OAEP")
	// ErrInvalidCiphertext is returned when an RSA ciphertext has the wrong size.
	ErrInvalidCiphertext = errors.New("RSA ciphertext has an invalid size")

	// ErrNotRSAKey is returned when the key type is not RSA.
	ErrNotRSAKey = errors.New("key type is not RSA")
)
