package gorsa

import (
	"crypto"
	"crypto/fips140"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"math/big"
	"testing"
)

func TestPSSSaltLength(t *testing.T) {
	priv, pub, err := GenerateKeys(2048)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("interoperable signature")
	sig, err := SignPSS(priv, msg)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(msg)
	if err := rsa.VerifyPSS(pub, crypto.SHA256, digest[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}); err != nil {
		t.Fatal(err)
	}
}

func TestMalformedPrivateKeyDoesNotPanic(t *testing.T) {
	key := &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 2047), big.NewInt(1)), E: 65537}}
	if _, err := PrivateKeyToPEM(key); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("error = %v", err)
	}
}

func TestFIPSPolicy(t *testing.T) {
	if !fips140.Enabled() {
		t.Skip("requires FIPS mode")
	}
	priv, pub, err := GenerateKeys(2048)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("FIPS RSA round trip")
	ct, err := EncryptOAEP(pub, msg, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecryptOAEP(priv, ct, nil)
	if err != nil || string(got) != string(msg) {
		t.Fatalf("decrypt = %q, %v", got, err)
	}
	sig, err := SignPSS(priv, msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPSS(pub, msg, sig); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPSS(pub, []byte("tampered"), sig); err == nil {
		t.Fatal("accepted tampered message")
	}
}
