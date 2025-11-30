# Go RSA Library

A simple and secure Go library for RSA encryption, decryption, signing, and verification. This library supports OAEP, PSS, and PKCS#1 v1.5 schemes and enforces NIST standards for key sizes.

## Features

- **Key Generation**: Generates RSA key pairs with a minimum size of 2048 bits (NIST standard).
- **Encryption/Decryption**:
  - RSA-OAEP (with SHA-256)
  - RSA-PKCS#1 v1.5
- **Signing/Verification**:
  - RSA-PSS (with SHA-256)
  - RSA-PKCS#1 v1.5 (with SHA-256)
- **Key Management**: Import and export keys in PEM format.

## Installation

```bash
go get github.com/fawwazid/go-rsa
```

## Usage

### Import the package

```go
import (
	"fmt"
	"log"

	gorsa "github.com/fawwazid/go-rsa"
)
```

### 1. Generate Keys

```go
// Generate a new RSA key pair (minimum 2048 bits)
priv, pub, err := gorsa.GenerateKeys(2048)
if err != nil {
    log.Fatalf("Failed to generate keys: %v", err)
}
```

### 2. Encryption and Decryption (OAEP)

Recommended for new applications.

```go
msg := []byte("Secret Message")
label := []byte("optional-label")

// Encrypt
ciphertext, err := gorsa.EncryptOAEP(pub, msg, label)
if err != nil {
    log.Fatal(err)
}

// Decrypt
plaintext, err := gorsa.DecryptOAEP(priv, ciphertext, label)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Decrypted: %s\n", plaintext)
```

### 3. Encryption and Decryption (PKCS#1 v1.5)

Supported for legacy compatibility.

```go
msg := []byte("Secret Message")

// Encrypt
ciphertext, err := gorsa.EncryptPKCS1v15(pub, msg)
if err != nil {
    log.Fatal(err)
}

// Decrypt
plaintext, err := gorsa.DecryptPKCS1v15(priv, ciphertext)
if err != nil {
    log.Fatal(err)
}
```

### 4. Signing and Verification (PSS)

Recommended for new applications.

```go
// Sign
signature, err := gorsa.SignPSS(priv, msg)
if err != nil {
    log.Fatal(err)
}

// Verify
err = gorsa.VerifyPSS(pub, msg, signature)
if err != nil {
    log.Fatal("Verification failed")
}
fmt.Println("Signature verified!")
```

### 5. Signing and Verification (PKCS#1 v1.5)

Supported for legacy compatibility.

```go
msg := []byte("Secret Message")

// Sign
signature, err := gorsa.SignPKCS1v15(priv, msg)
if err != nil {
    log.Fatal(err)
}

// Verify
err = gorsa.VerifyPKCS1v15(pub, msg, signature)
if err != nil {
    log.Fatal("Verification failed")
}
```

### 6. Export and Import Keys (PEM)

```go
// Export to PEM
privPEM, err := gorsa.PrivateKeyToPEM(priv)
if err != nil {
    log.Fatal(err)
}
pubPEM, err := gorsa.PublicKeyToPEM(pub)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Private Key:\n%s\n", privPEM)
fmt.Printf("Public Key:\n%s\n", pubPEM)

// Import from PEM
parsedPriv, err := gorsa.ParsePrivateKeyFromPEM(privPEM)
if err != nil {
    log.Fatal(err)
}

parsedPub, err := gorsa.ParsePublicKeyFromPEM(pubPEM)
if err != nil {
    log.Fatal(err)
}
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
