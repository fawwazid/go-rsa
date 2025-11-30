package tests

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
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
	privPEM, err := gorsa.PrivateKeyToPEM(priv)
	if err != nil {
		t.Fatalf("Failed to convert private key to PEM: %v", err)
	}
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

func TestParsePrivateKeyFromPEMErrors(t *testing.T) {
	// Test with invalid PEM data
	invalidPEM := []byte("this is not valid PEM data")
	_, err := gorsa.ParsePrivateKeyFromPEM(invalidPEM)
	if err == nil {
		t.Error("Expected error for invalid PEM data, got nil")
	}

	// Test with empty PEM data
	_, err = gorsa.ParsePrivateKeyFromPEM([]byte{})
	if err == nil {
		t.Error("Expected error for empty PEM data, got nil")
	}
}

func TestParsePublicKeyFromPEMErrors(t *testing.T) {
	// Test with invalid PEM data
	invalidPEM := []byte("this is not valid PEM data")
	_, err := gorsa.ParsePublicKeyFromPEM(invalidPEM)
	if err == nil {
		t.Error("Expected error for invalid PEM data, got nil")
	}

	// Test with empty PEM data
	_, err = gorsa.ParsePublicKeyFromPEM([]byte{})
	if err == nil {
		t.Error("Expected error for empty PEM data, got nil")
	}

	// Test with non-RSA key (ECDSA)
	ecdsaPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}
	ecdsaPubBytes, err := x509.MarshalPKIXPublicKey(&ecdsaPriv.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal ECDSA public key: %v", err)
	}
	ecdsaPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: ecdsaPubBytes,
	})
	_, err = gorsa.ParsePublicKeyFromPEM(ecdsaPEM)
	if err == nil {
		t.Error("Expected error for non-RSA key, got nil")
	}
}

func TestDecryptOAEPErrors(t *testing.T) {
	priv, pub, err := gorsa.GenerateKeys(2048)
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	msg := []byte("Hello, RSA!")
	label := []byte("test-label")

	ciphertext, err := gorsa.EncryptOAEP(pub, msg, label)
	if err != nil {
		t.Fatalf("Failed to encrypt OAEP: %v", err)
	}

	// Test decryption with mismatched label
	wrongLabel := []byte("wrong-label")
	_, err = gorsa.DecryptOAEP(priv, ciphertext, wrongLabel)
	if err == nil {
		t.Error("Expected error for mismatched label, got nil")
	}

	// Test decryption with corrupted ciphertext
	corruptedCiphertext := make([]byte, len(ciphertext))
	copy(corruptedCiphertext, ciphertext)
	corruptedCiphertext[0] ^= 0xFF // Flip bits in first byte
	_, err = gorsa.DecryptOAEP(priv, corruptedCiphertext, label)
	if err == nil {
		t.Error("Expected error for corrupted ciphertext, got nil")
	}

	// Test decryption with wrong key
	priv2, _, err := gorsa.GenerateKeys(2048)
	if err != nil {
		t.Fatalf("Failed to generate second key pair: %v", err)
	}
	_, err = gorsa.DecryptOAEP(priv2, ciphertext, label)
	if err == nil {
		t.Error("Expected error for wrong key, got nil")
	}
}

func TestVerifyPSSErrors(t *testing.T) {
	priv, pub, err := gorsa.GenerateKeys(2048)
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	msg := []byte("Hello, RSA!")

	signature, err := gorsa.SignPSS(priv, msg)
	if err != nil {
		t.Fatalf("Failed to sign PSS: %v", err)
	}

	// Test verification with corrupted signature
	corruptedSignature := make([]byte, len(signature))
	copy(corruptedSignature, signature)
	corruptedSignature[0] ^= 0xFF // Flip bits in first byte
	err = gorsa.VerifyPSS(pub, msg, corruptedSignature)
	if err == nil {
		t.Error("Expected error for corrupted signature, got nil")
	}

	// Test verification with modified message
	modifiedMsg := []byte("Modified message!")
	err = gorsa.VerifyPSS(pub, modifiedMsg, signature)
	if err == nil {
		t.Error("Expected error for modified message, got nil")
	}

	// Test verification with wrong key
	_, pub2, err := gorsa.GenerateKeys(2048)
	if err != nil {
		t.Fatalf("Failed to generate second key pair: %v", err)
	}
	err = gorsa.VerifyPSS(pub2, msg, signature)
	if err == nil {
		t.Error("Expected error for wrong key, got nil")
	}
}

func TestVerifyPKCS1v15Errors(t *testing.T) {
	priv, pub, err := gorsa.GenerateKeys(2048)
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	msg := []byte("Hello, RSA!")

	signature, err := gorsa.SignPKCS1v15(priv, msg)
	if err != nil {
		t.Fatalf("Failed to sign PKCS1v15: %v", err)
	}

	// Test verification with corrupted signature
	corruptedSignature := make([]byte, len(signature))
	copy(corruptedSignature, signature)
	corruptedSignature[0] ^= 0xFF // Flip bits in first byte
	err = gorsa.VerifyPKCS1v15(pub, msg, corruptedSignature)
	if err == nil {
		t.Error("Expected error for corrupted signature, got nil")
	}

	// Test verification with modified message
	modifiedMsg := []byte("Modified message!")
	err = gorsa.VerifyPKCS1v15(pub, modifiedMsg, signature)
	if err == nil {
		t.Error("Expected error for modified message, got nil")
	}

	// Test verification with wrong key
	_, pub2, err := gorsa.GenerateKeys(2048)
	if err != nil {
		t.Fatalf("Failed to generate second key pair: %v", err)
	}
	err = gorsa.VerifyPKCS1v15(pub2, msg, signature)
	if err == nil {
		t.Error("Expected error for wrong key, got nil")
	}
}

func TestDecryptPKCS1v15Errors(t *testing.T) {
	priv, pub, err := gorsa.GenerateKeys(2048)
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	msg := []byte("Hello, RSA!")

	ciphertext, err := gorsa.EncryptPKCS1v15(pub, msg)
	if err != nil {
		t.Fatalf("Failed to encrypt PKCS1v15: %v", err)
	}

	// Test decryption with corrupted ciphertext
	corruptedCiphertext := make([]byte, len(ciphertext))
	copy(corruptedCiphertext, ciphertext)
	corruptedCiphertext[0] ^= 0xFF // Flip bits in first byte
	_, err = gorsa.DecryptPKCS1v15(priv, corruptedCiphertext)
	if err == nil {
		t.Error("Expected error for corrupted ciphertext, got nil")
	}

	// Test decryption with wrong key
	priv2, _, err := gorsa.GenerateKeys(2048)
	if err != nil {
		t.Fatalf("Failed to generate second key pair: %v", err)
	}
	_, err = gorsa.DecryptPKCS1v15(priv2, ciphertext)
	if err == nil {
		t.Error("Expected error for wrong key, got nil")
	}
}

func TestNilKeyValidation(t *testing.T) {
	priv, pub, err := gorsa.GenerateKeys(2048)
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	msg := []byte("Hello, RSA!")
	label := []byte("test-label")

	// Test EncryptOAEP with nil public key
	_, err = gorsa.EncryptOAEP(nil, msg, label)
	if err == nil {
		t.Error("Expected error for nil public key in EncryptOAEP, got nil")
	}

	// Test DecryptOAEP with nil private key
	ciphertext, _ := gorsa.EncryptOAEP(pub, msg, label)
	_, err = gorsa.DecryptOAEP(nil, ciphertext, label)
	if err == nil {
		t.Error("Expected error for nil private key in DecryptOAEP, got nil")
	}

	// Test EncryptPKCS1v15 with nil public key
	_, err = gorsa.EncryptPKCS1v15(nil, msg)
	if err == nil {
		t.Error("Expected error for nil public key in EncryptPKCS1v15, got nil")
	}

	// Test DecryptPKCS1v15 with nil private key
	ciphertextPKCS, _ := gorsa.EncryptPKCS1v15(pub, msg)
	_, err = gorsa.DecryptPKCS1v15(nil, ciphertextPKCS)
	if err == nil {
		t.Error("Expected error for nil private key in DecryptPKCS1v15, got nil")
	}

	// Test SignPSS with nil private key
	_, err = gorsa.SignPSS(nil, msg)
	if err == nil {
		t.Error("Expected error for nil private key in SignPSS, got nil")
	}

	// Test VerifyPSS with nil public key
	signaturePSS, _ := gorsa.SignPSS(priv, msg)
	err = gorsa.VerifyPSS(nil, msg, signaturePSS)
	if err == nil {
		t.Error("Expected error for nil public key in VerifyPSS, got nil")
	}

	// Test SignPKCS1v15 with nil private key
	_, err = gorsa.SignPKCS1v15(nil, msg)
	if err == nil {
		t.Error("Expected error for nil private key in SignPKCS1v15, got nil")
	}

	// Test VerifyPKCS1v15 with nil public key
	signaturePKCS, _ := gorsa.SignPKCS1v15(priv, msg)
	err = gorsa.VerifyPKCS1v15(nil, msg, signaturePKCS)
	if err == nil {
		t.Error("Expected error for nil public key in VerifyPKCS1v15, got nil")
	}

	// Test PrivateKeyToPEM with nil private key
	_, err = gorsa.PrivateKeyToPEM(nil)
	if err == nil {
		t.Error("Expected error for nil private key in PrivateKeyToPEM, got nil")
	}

	// Test PublicKeyToPEM with nil public key
	_, err = gorsa.PublicKeyToPEM(nil)
	if err == nil {
		t.Error("Expected error for nil public key in PublicKeyToPEM, got nil")
	}
}
