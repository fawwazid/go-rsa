# go-rsa

Install: `go get github.com/fawwazid/go-rsa/v2@v2.0.0`.
See [v2 release notes](CHANGELOG.md) for breaking changes.

RSA-OAEP encryption and RSA-PSS signatures with SHA-256. Requires Go 1.27.3.

## Usage

```go
package main

import (
 "fmt"
 "log"
 gorsa "github.com/fawwazid/go-rsa/v2"
)

func main() {
 privateKey, publicKey, err := gorsa.GenerateKeys(3072)
 if err != nil { log.Fatal(err) }
 message := []byte("short message")
 signature, err := gorsa.SignPSS(privateKey, message)
 if err != nil { log.Fatal(err) }
 if err := gorsa.VerifyPSS(publicKey, message, signature); err != nil { log.Fatal(err) }
 encoded, err := gorsa.PrivateKeyToPEM(privateKey)
 if err != nil { log.Fatal(err) }
 fmt.Println(len(encoded))
}
```

## API and key formats

- `GenerateKeys(bits)`: 2048–8192 bits; choose 3072 where 128-bit security
  strength is required. The upper bound limits resource consumption.
- `EncryptOAEP` / `DecryptOAEP`: SHA-256, with the same optional label.
  Use authenticated symmetric encryption for bulk data.
- `SignPSS` / `VerifyPSS`: SHA-256 and exactly 32 salt bytes in every mode.
- `PrivateKeyToPEM` / `ParsePrivateKeyFromPEM`: PKCS#8 `PRIVATE KEY`.
- `PublicKeyToPEM` / `ParsePublicKeyFromPEM`: PKIX `PUBLIC KEY`.

Keys require two primes and valid private-key structure. PEM imports are capped
at 1 MiB and require one correctly typed block, no preamble, no PEM headers,
and no trailing payload.
Private-key export is **unencrypted**; protect it through application storage.

## Semantic versioning

Releases use Semantic Versioning through Release Please. A push to `main`
opens or updates a release pull request. Merging that generated pull request
creates the version tag and GitHub release.

Use Conventional Commits in pull request titles (the squash-merge message):

- `fix: ...`, including `fix(security): ...`, creates a patch release.
- `feat: ...` creates a minor release.
- `fix!: ...`, `feat!: ...`, or a `BREAKING CHANGE:` footer creates a
  major release.
- `docs:`, `test:`, `chore:`, and `ci:` do not trigger a release.

A `security:` commit appears under Security in generated release notes, but
does not trigger a version bump by itself. Do not edit the generated changelog
manually.
## Breaking changes

PKCS#1 v1.5 encryption, decryption, signing, and verification APIs have been
removed. PKCS#1 `RSA PRIVATE KEY` input is rejected; only PKCS#8 is supported.
PSS verification no longer auto-detects arbitrary salt lengths.
No aliases, automatic format conversion, or alternate verification path remain.

See [SECURITY.md](SECURITY.md) for FIPS requirements. OAEP alone is not a
complete SP 800-56B key-establishment protocol.
Run `go test ./...` and `go vet ./...`. License: [MIT](LICENSE).
