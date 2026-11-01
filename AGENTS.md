# Agent instructions

This repository is the `go-rsa` Go module. Keep changes within this module
unless the task explicitly spans other repositories. Preserve existing user
changes. Do not create or edit changelogs; Release Please generates them.

## Security and API

- Keep RSA-OAEP and RSA-PSS fixed to SHA-256; PSS uses exactly a 32-byte salt.
- Preserve key-size and PEM input bounds, strict single-block parsing, and
  private-key validation.
- Never restore RSA PKCS#1 v1.5 operations or permissive key parsing.
- OAEP for short-message encryption is not a complete SP 800-56B key
  establishment protocol. Recommend authenticated symmetric encryption for
  bulk data and do not claim this package is independently FIPS-certified.
- Describe FIPS use as conditional on the validated module, approved mode, and
  operating environment.

## Development

- Workspace mail invariant: `go-mail` caps messages at 1,000 recipients, 100
  attachments, and 25 MiB; untrusted attachment bytes use its checked API.
- Workspace MFA invariant: `ConstantTimeCompare` rejects strings longer than
  4,096 UTF-8 bytes before allocating byte slices.

- Target the Go version in `go.mod`; format Go changes with `gofmt`.
- Keep README and security documentation aligned with algorithms, key formats,
  and FIPS limitations.
- Remove only clearly unused internal code; preserve exported APIs unless a
  breaking change is explicitly requested.
- Add or update regression tests for every code change and run the affected
  module's complete test suite before finishing. Run `go vet ./...` as well.
- Review RSA changes against applicable NIST SP 800-56B, SP 800-131A, FIPS,
  and OWASP guidance. Do not present generic OAEP encryption as complete key
  establishment.
- For every workspace code, test, or security-policy change, review and update
  all eight module-level `AGENTS.md` files in the same change set so their
  constraints and test-coverage notes stay aligned. Keep updates concise; this
  is not a changelog.

## Test coverage notes

- RSA tests cover OAEP maximum plaintext and ciphertext length, key-size bounds,
  strict PEM preamble handling, and PEM input-size bounds.
