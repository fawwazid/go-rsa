package gorsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

// EncryptOAEP encrypts the given data with RSA-OAEP using SHA256.
//
// It takes the recipient's public key, the message to encrypt, and an optional label.
// The label parameter can be nil or an empty slice ([]byte{}) if not needed.
// The label is not encrypted but is bound to the message, ensuring that the
// ciphertext cannot be decrypted with a different label.
//
// Compliance: NIST SP 800-56B Rev. 2 recommends RSA-OAEP for encryption.
//
// Returns the encrypted ciphertext or an error if encryption fails.
func EncryptOAEP(pub *rsa.PublicKey, msg []byte, label []byte) ([]byte, error) {
	if pub == nil {
		return nil, ErrNilPublicKey
	}
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, msg, label)
}

// DecryptOAEP decrypts the given data with RSA-OAEP using SHA256.
//
// It takes the recipient's private key, the ciphertext to decrypt, and the optional label
// used during encryption. The label must match the one used for encryption.
//
// Compliance: NIST SP 800-56B Rev. 2 recommends RSA-OAEP for encryption.
//
// Returns the decrypted plaintext or an error if decryption fails.
func DecryptOAEP(priv *rsa.PrivateKey, ciphertext []byte, label []byte) ([]byte, error) {
	if priv == nil {
		return nil, ErrNilPrivateKey
	}
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, ciphertext, label)
}

// EncryptPKCS1v15 encrypts the given data with RSA-PKCS#1 v1.5.
//
// Note: This scheme is less secure than OAEP and is included for legacy compatibility.
// New applications should prefer EncryptOAEP.
//
// Deprecated: NIST SP 800-56B Rev. 2 deprecates RSAES-PKCS1-v1_5. Use RSA-OAEP instead.
//
// Returns the encrypted ciphertext or an error if encryption fails.
func EncryptPKCS1v15(pub *rsa.PublicKey, msg []byte) ([]byte, error) {
	if pub == nil {
		return nil, ErrNilPublicKey
	}
	return rsa.EncryptPKCS1v15(rand.Reader, pub, msg)
}

// DecryptPKCS1v15 decrypts the given data with RSA-PKCS#1 v1.5.
//
// Note: This scheme is susceptible to padding oracle attacks.
// New applications should prefer DecryptOAEP.
//
// Deprecated: NIST SP 800-56B Rev. 2 deprecates RSAES-PKCS1-v1_5. Use RSA-OAEP instead.
//
// Returns the decrypted plaintext or an error if decryption fails.
func DecryptPKCS1v15(priv *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	if priv == nil {
		return nil, ErrNilPrivateKey
	}
	return rsa.DecryptPKCS1v15(rand.Reader, priv, ciphertext)
}

// SignPSS signs the given data with RSA-PSS using SHA256.
//
// It calculates the SHA-256 hash of the message and signs it using the PSS scheme.
// PSS is a probabilistic signature scheme and is recommended for new applications.
//
// Compliance: NIST SP 800-57 Part 1 Rev. 5 recommends RSA-PSS for digital signatures.
//
// Returns the signature or an error if signing fails.
func SignPSS(priv *rsa.PrivateKey, msg []byte) ([]byte, error) {
	if priv == nil {
		return nil, ErrNilPrivateKey
	}
	hashed := sha256.Sum256(msg)
	return rsa.SignPSS(rand.Reader, priv, crypto.SHA256, hashed[:], nil)
}

// VerifyPSS verifies the signature with RSA-PSS using SHA256.
//
// It calculates the SHA-256 hash of the message and verifies the signature against
// the public key using the PSS scheme.
//
// Compliance: NIST SP 800-57 Part 1 Rev. 5 recommends RSA-PSS for digital signatures.
//
// Returns nil if the signature is valid, or an error otherwise.
func VerifyPSS(pub *rsa.PublicKey, msg, signature []byte) error {
	if pub == nil {
		return ErrNilPublicKey
	}
	hashed := sha256.Sum256(msg)
	return rsa.VerifyPSS(pub, crypto.SHA256, hashed[:], signature, nil)
}

// SignPKCS1v15 signs the given data with RSA-PKCS#1 v1.5 using SHA256.
//
// It calculates the SHA-256 hash of the message and signs it using the PKCS#1 v1.5 scheme.
//
// Compliance: Acceptable under NIST SP 800-131A Rev. 2, but RSA-PSS is preferred for new applications.
//
// Returns the signature or an error if signing fails.
func SignPKCS1v15(priv *rsa.PrivateKey, msg []byte) ([]byte, error) {
	if priv == nil {
		return nil, ErrNilPrivateKey
	}
	hashed := sha256.Sum256(msg)
	return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hashed[:])
}

// VerifyPKCS1v15 verifies the signature with RSA-PKCS#1 v1.5 using SHA256.
//
// It calculates the SHA-256 hash of the message and verifies the signature against
// the public key using the PKCS#1 v1.5 scheme.
//
// Compliance: Acceptable under NIST SP 800-131A Rev. 2, but RSA-PSS is preferred for new applications.
//
// Returns nil if the signature is valid, or an error otherwise.
func VerifyPKCS1v15(pub *rsa.PublicKey, msg, signature []byte) error {
	if pub == nil {
		return ErrNilPublicKey
	}
	hashed := sha256.Sum256(msg)
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, hashed[:], signature)
}
