package gorsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

// EncryptOAEP encrypts the given data with RSA-OAEP using SHA256.
func EncryptOAEP(pub *rsa.PublicKey, msg []byte, label []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, msg, label)
}

// DecryptOAEP decrypts the given data with RSA-OAEP using SHA256.
func DecryptOAEP(priv *rsa.PrivateKey, ciphertext []byte, label []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, ciphertext, label)
}

// EncryptPKCS1v15 encrypts the given data with RSA-PKCS#1 v1.5.
func EncryptPKCS1v15(pub *rsa.PublicKey, msg []byte) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, pub, msg)
}

// DecryptPKCS1v15 decrypts the given data with RSA-PKCS#1 v1.5.
func DecryptPKCS1v15(priv *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	return rsa.DecryptPKCS1v15(rand.Reader, priv, ciphertext)
}

// SignPSS signs the given data with RSA-PSS using SHA256.
func SignPSS(priv *rsa.PrivateKey, msg []byte) ([]byte, error) {
	hashed := sha256.Sum256(msg)
	return rsa.SignPSS(rand.Reader, priv, crypto.SHA256, hashed[:], nil)
}

// VerifyPSS verifies the signature with RSA-PSS using SHA256.
func VerifyPSS(pub *rsa.PublicKey, msg, signature []byte) error {
	hashed := sha256.Sum256(msg)
	return rsa.VerifyPSS(pub, crypto.SHA256, hashed[:], signature, nil)
}

// SignPKCS1v15 signs the given data with RSA-PKCS#1 v1.5 using SHA256.
func SignPKCS1v15(priv *rsa.PrivateKey, msg []byte) ([]byte, error) {
	hashed := sha256.Sum256(msg)
	return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hashed[:])
}

// VerifyPKCS1v15 verifies the signature with RSA-PKCS#1 v1.5 using SHA256.
func VerifyPKCS1v15(pub *rsa.PublicKey, msg, signature []byte) error {
	hashed := sha256.Sum256(msg)
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, hashed[:], signature)
}
