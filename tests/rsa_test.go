package tests

import (
	"testing"

	gorsa "github.com/fawwazid/go-rsa"
)

func TestRSA(t *testing.T) {
	// 1. Generate Keys
	priv, pub, err := gorsa.GenerateKeys(2048)
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	msg := []byte("Hello, RSA!")
	label := []byte("test-label")

	// 2. OAEP Encryption/Decryption
	ciphertextOAEP, err := gorsa.EncryptOAEP(pub, msg, label)
	if err != nil {
		t.Fatalf("Failed to encrypt OAEP: %v", err)
	}
	plaintextOAEP, err := gorsa.DecryptOAEP(priv, ciphertextOAEP, label)
	if err != nil {
		t.Fatalf("Failed to decrypt OAEP: %v", err)
	}
	if string(plaintextOAEP) != string(msg) {
		t.Errorf("OAEP decryption mismatch: got %s, want %s", plaintextOAEP, msg)
	}

	// 3. PKCS#1 v1.5 Encryption/Decryption
	ciphertextPKCS1v15, err := gorsa.EncryptPKCS1v15(pub, msg)
	if err != nil {
		t.Fatalf("Failed to encrypt PKCS1v15: %v", err)
	}
	plaintextPKCS1v15, err := gorsa.DecryptPKCS1v15(priv, ciphertextPKCS1v15)
	if err != nil {
		t.Fatalf("Failed to decrypt PKCS1v15: %v", err)
	}
	if string(plaintextPKCS1v15) != string(msg) {
		t.Errorf("PKCS1v15 decryption mismatch: got %s, want %s", plaintextPKCS1v15, msg)
	}

	// 4. PSS Signing/Verification
	signaturePSS, err := gorsa.SignPSS(priv, msg)
	if err != nil {
		t.Fatalf("Failed to sign PSS: %v", err)
	}
	err = gorsa.VerifyPSS(pub, msg, signaturePSS)
	if err != nil {
		t.Errorf("Failed to verify PSS signature: %v", err)
	}

	// 5. PKCS#1 v1.5 Signing/Verification
	signaturePKCS1v15, err := gorsa.SignPKCS1v15(priv, msg)
	if err != nil {
		t.Fatalf("Failed to sign PKCS1v15: %v", err)
	}
	err = gorsa.VerifyPKCS1v15(pub, msg, signaturePKCS1v15)
	if err != nil {
		t.Errorf("Failed to verify PKCS1v15 signature: %v", err)
	}

	// 6. PEM Encoding/Decoding
	privPEM := gorsa.PrivateKeyToPEM(priv)
	pubPEM, err := gorsa.PublicKeyToPEM(pub)
	if err != nil {
		t.Fatalf("Failed to convert public key to PEM: %v", err)
	}

	parsedPriv, err := gorsa.ParsePrivateKeyFromPEM(privPEM)
	if err != nil {
		t.Fatalf("Failed to parse private key from PEM: %v", err)
	}
	if !parsedPriv.Equal(priv) {
		t.Error("Parsed private key does not match original")
	}

	parsedPub, err := gorsa.ParsePublicKeyFromPEM(pubPEM)
	if err != nil {
		t.Fatalf("Failed to parse public key from PEM: %v", err)
	}
	if !parsedPub.Equal(pub) {
		t.Error("Parsed public key does not match original")
	}
}

func TestGenerateKeysValidation(t *testing.T) {
	// Test with invalid key size
	_, _, err := gorsa.GenerateKeys(1024)
	if err == nil {
		t.Error("Expected error for key size < 2048, got nil")
	}

	// Test with valid key size
	_, _, err = gorsa.GenerateKeys(2048)
	if err != nil {
		t.Errorf("Expected no error for key size 2048, got %v", err)
	}
}
