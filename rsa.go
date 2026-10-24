// Package gorsa provides RSA-OAEP encryption and RSA-PSS signatures using SHA-256.
package gorsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

// EncryptOAEP encrypts a short message with RSA-OAEP/SHA-256.
// Use authenticated symmetric encryption for bulk data.
func EncryptOAEP(pub *rsa.PublicKey, msg, label []byte) ([]byte, error) {
	if err := validatePublicKey(pub); err != nil {
		return nil, err
	}
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, msg, label)
}

// DecryptOAEP decrypts RSA-OAEP/SHA-256 ciphertext with the matching label.
func DecryptOAEP(priv *rsa.PrivateKey, ciphertext, label []byte) ([]byte, error) {
	if err := validatePrivateKey(priv); err != nil {
		return nil, err
	}
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, ciphertext, label)
}

// SignPSS signs a message with RSA-PSS/SHA-256 and a 32-byte salt.
func SignPSS(priv *rsa.PrivateKey, msg []byte) ([]byte, error) {
	if err := validatePrivateKey(priv); err != nil {
		return nil, err
	}
	digest := sha256.Sum256(msg)
	return rsa.SignPSS(rand.Reader, priv, crypto.SHA256, digest[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
}

// VerifyPSS accepts RSA-PSS/SHA-256 signatures with exactly a 32-byte salt.
func VerifyPSS(pub *rsa.PublicKey, msg, signature []byte) error {
	if err := validatePublicKey(pub); err != nil {
		return err
	}
	digest := sha256.Sum256(msg)
	return rsa.VerifyPSS(pub, crypto.SHA256, digest[:], signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
}
