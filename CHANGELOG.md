# Changelog

## [3.0.0](https://github.com/fawwazid/go-rsa/compare/v2.0.0...v3.0.0) (2026-11-01)


### ⚠ BREAKING CHANGES

* prepare v2 security refactor ([#11](https://github.com/fawwazid/go-rsa/issues/11))

### Features

* enhance RSA functions with detailed documentation and compliance notes ([ab78c6c](https://github.com/fawwazid/go-rsa/commit/ab78c6c954bcb0d16893398926656c142fd5deb0))
* Implement comprehensive RSA encryption, decryption, signing, ve… ([1c3c292](https://github.com/fawwazid/go-rsa/commit/1c3c292d8c2fd8fadb42a058cd33e019d997343a))
* Implement comprehensive RSA encryption, decryption, signing, verification, and PEM utility functions with full test coverage. ([3fb1e8c](https://github.com/fawwazid/go-rsa/commit/3fb1e8cc3c557f39b8d94b39aa6ffa06db4ee181))
* implement RSA library with OAEP, PSS, and PKCS[#1](https://github.com/fawwazid/go-rsa/issues/1) v1.5 support ([963157a](https://github.com/fawwazid/go-rsa/commit/963157a96842867026d53d553292ad2d72fcfbfa))
* prepare v2 security refactor ([#11](https://github.com/fawwazid/go-rsa/issues/11)) ([5cc1fee](https://github.com/fawwazid/go-rsa/commit/5cc1fee64e2d558a8141bdf20060a69e1c97c807))


### Bug Fixes

* address PR review comments - fix PEM type and add error handling tests ([0f6a6d5](https://github.com/fawwazid/go-rsa/commit/0f6a6d56d5a5fc15748c27dfbbf8636524f56888))

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

## v1.0.2 — 2026-10-15

- Harden RSA key validation and update dependencies.

## v1.0.1 — 2025-12-30

- Add sentinel errors and improve NIST compliance documentation.

## v1.0.0 — 2025-11-30

- Initial release with RSA OAEP, PSS, and PKCS#1 v1.5 support.
