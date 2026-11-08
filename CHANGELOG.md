# Changelog

## [2.0.2](https://github.com/fawwazid/go-rsa/compare/v2.0.1...v2.0.2) (2026-11-08)


### Documentation

* document branch and pull request workflow ([32add48](https://github.com/fawwazid/go-rsa/commit/32add48366dc56e270f5bd0957adfdb643f428c6))

## [2.0.1](https://github.com/fawwazid/go-rsa/compare/v2.0.0...v2.0.1) (2026-11-01)


### Bug Fixes

* **release:** configure semantic versioning ([#14](https://github.com/fawwazid/go-rsa/issues/14)) ([dd51845](https://github.com/fawwazid/go-rsa/commit/dd518450c1090577ee5e69fe69b0e2f6e543a989))


### Chores

* configure Google Release Please ([e88228d](https://github.com/fawwazid/go-rsa/commit/e88228d32abc85a295e4cd1ba1714169fdfcd877))
* reset Release Please baseline ([12e432e](https://github.com/fawwazid/go-rsa/commit/12e432e7cff3fe273ab3101e533bda2bf372635e))


### Security

* bound RSA keys and PEM parsing ([#13](https://github.com/fawwazid/go-rsa/issues/13)) ([a1801fb](https://github.com/fawwazid/go-rsa/commit/a1801fba2777d619c98329605c3097d9c4aababe))

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
