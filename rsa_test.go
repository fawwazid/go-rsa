package gorsa_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

	gorsa "github.com/fawwazid/go-rsa/v2"
)

func TestRSA(t *testing.T) {
	priv, pub, err := gorsa.GenerateKeys(2048)
	if err != nil {
		t.Fatal(err)
	}
	msg, label := []byte("message"), []byte("context")
	ciphertext, err := gorsa.EncryptOAEP(pub, msg, label)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := gorsa.DecryptOAEP(priv, ciphertext, label)
	if err != nil || !bytes.Equal(plaintext, msg) {
		t.Fatalf("decrypt = %q, %v", plaintext, err)
	}
	if _, err := gorsa.DecryptOAEP(priv, ciphertext, []byte("wrong")); err == nil {
		t.Fatal("accepted wrong label")
	}
	ciphertext[0] ^= 1
	if _, err := gorsa.DecryptOAEP(priv, ciphertext, label); err == nil {
		t.Fatal("accepted tampered ciphertext")
	}
	signature, err := gorsa.SignPSS(priv, msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := gorsa.VerifyPSS(pub, msg, signature); err != nil {
		t.Fatal(err)
	}
	if err := gorsa.VerifyPSS(pub, []byte("changed"), signature); err == nil {
		t.Fatal("accepted changed message")
	}
	signature[0] ^= 1
	if err := gorsa.VerifyPSS(pub, msg, signature); err == nil {
		t.Fatal("accepted damaged signature")
	}
}

func TestStrictPSSSalt(t *testing.T) {
	priv, pub, err := gorsa.GenerateKeys(2048)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("message")
	digest := sha256.Sum256(msg)
	signature, err := rsa.SignPSS(rand.Reader, priv, crypto.SHA256, digest[:], &rsa.PSSOptions{SaltLength: 16})
	if err != nil {
		t.Fatal(err)
	}
	if err := gorsa.VerifyPSS(pub, msg, signature); err == nil {
		t.Fatal("accepted a salt other than 32 bytes")
	}
}

func TestPEMFormats(t *testing.T) {
	priv, pub, err := gorsa.GenerateKeys(2048)
	if err != nil {
		t.Fatal(err)
	}
	privatePEM, err := gorsa.PrivateKeyToPEM(priv)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(privatePEM)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatal("expected PKCS#8 PRIVATE KEY")
	}
	if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		t.Fatal(err)
	}
	parsed, err := gorsa.ParsePrivateKeyFromPEM(privatePEM)
	if err != nil || parsed.N.Cmp(priv.N) != 0 {
		t.Fatalf("private key round trip = %v", err)
	}
	publicPEM, err := gorsa.PublicKeyToPEM(pub)
	if err != nil {
		t.Fatal(err)
	}
	parsedPublic, err := gorsa.ParsePublicKeyFromPEM(publicPEM)
	if err != nil || parsedPublic.N.Cmp(pub.N) != 0 {
		t.Fatalf("public key round trip = %v", err)
	}
	oldPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	if _, err := gorsa.ParsePrivateKeyFromPEM(oldPEM); !errors.Is(err, gorsa.ErrInvalidPEM) {
		t.Fatalf("accepted PKCS#1 key: %v", err)
	}
	if _, err := gorsa.ParsePrivateKeyFromPEM(append(privatePEM, []byte("payload")...)); !errors.Is(err, gorsa.ErrInvalidPEM) {
		t.Fatalf("accepted trailing payload: %v", err)
	}
	if _, err := gorsa.ParsePublicKeyFromPEM(append(publicPEM, publicPEM...)); !errors.Is(err, gorsa.ErrInvalidPEM) {
		t.Fatalf("accepted extra block: %v", err)
	}
	if _, err := gorsa.ParsePrivateKeyFromPEM([]byte("invalid")); !errors.Is(err, gorsa.ErrInvalidPEM) {
		t.Fatal(err)
	}
	if _, err := gorsa.ParsePublicKeyFromPEM([]byte("invalid")); !errors.Is(err, gorsa.ErrInvalidPEM) {
		t.Fatal(err)
	}
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, err := x509.MarshalPKCS8PrivateKey(ec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gorsa.ParsePrivateKeyFromPEM(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ecDER})); !errors.Is(err, gorsa.ErrNotRSAKey) {
		t.Fatal(err)
	}
}

func TestKeyValidation(t *testing.T) {
	if _, _, err := gorsa.GenerateKeys(1024); !errors.Is(err, gorsa.ErrKeySizeTooSmall) {
		t.Fatal(err)
	}
	for _, call := range []func() error{
		func() error { _, err := gorsa.EncryptOAEP(nil, nil, nil); return err },
		func() error { _, err := gorsa.DecryptOAEP(nil, nil, nil); return err },
		func() error { _, err := gorsa.SignPSS(nil, nil); return err },
		func() error { return gorsa.VerifyPSS(nil, nil, nil) },
		func() error { _, err := gorsa.PrivateKeyToPEM(nil); return err },
		func() error { _, err := gorsa.PublicKeyToPEM(nil); return err },
	} {
		if err := call(); err == nil {
			t.Fatal("accepted nil key")
		}
	}
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gorsa.EncryptOAEP(&weak.PublicKey, nil, nil); !errors.Is(err, gorsa.ErrKeySizeTooSmall) {
		t.Fatal(err)
	}
	if _, err := gorsa.SignPSS(weak, nil); !errors.Is(err, gorsa.ErrKeySizeTooSmall) {
		t.Fatal(err)
	}
}
