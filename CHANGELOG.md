# Changelog

## v2.0.0 — 2026-10-24

Keep SHA-256 OAEP/PSS with strict signatures and modern PEM keys.

### Breaking changes

- Module path is now `github.com/fawwazid/go-rsa/v2`. Update imports and use Go 1.27.3 or later.
- Remove PKCS#1 v1.5 encryption, decryption, signing, and verification wrappers.
- Use PKCS#8 PRIVATE KEY for private-key serialization; reject PKCS#1 private keys.
- Require exactly 32-byte PSS salts in every runtime mode.

### Security and maintenance

- Validate key structure and minimum 2048-bit size before use or serialization.
- Reject unexpected PEM block types, headers, and trailing payloads.
- Private-key export is unencrypted and must be protected by the consuming application.
- Remove redundant code, obsolete comments, and compatibility paths.
- Add regression tests, current README examples, security guidance, and CI for Linux and Windows.
- FIPS policy tests use the frozen Go module v1.0.0 in both approved and strict assessment modes. This library is not independently FIPS certified; consult SECURITY.md for deployment requirements.

### Install

```sh
go get github.com/fawwazid/go-rsa/v2@v2.0.0
```
