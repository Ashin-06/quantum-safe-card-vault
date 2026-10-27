# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately, through GitHub's private vulnerability
reporting on this repository (Security → Report a vulnerability) or by contacting the
maintainer, [@Ashin-06](https://github.com/Ashin-06), directly. Do not open a public issue.

Include what you found, how to reproduce it and what an attacker could do with it. You should
get an acknowledgement within 5 working days. Please give us 90 days to fix an issue before
disclosing it, and don't test against anyone else's deployment.

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | yes |
| < 1.0 | no (prototype releases) |

## Scope

In scope: the vault service, FF1 tokenization, the hybrid KEM envelopes, DUKPT-style key
derivation, key sealing and rotation, the audit chain, the container image and the CI
configuration in this repository. Getting a PAN out for a merchant you don't hold a key for is the
most serious kind of finding.

Out of scope: your reverse proxy or TLS setup, and findings that need an already-compromised host
or a leaked API key with the matching role.

**What is and isn't vetted cryptography.** ML-KEM-768, X25519, AES-GCM, HKDF and HMAC come from
pyca `cryptography`. Written here, and **not reviewed by a cryptographer**:
- FF1 (SP 800-38G Rev. 1), in Python; it matches the nine NIST sample vectors;
- the DUKPT-style derivation, which is modelled on ANSI X9.24 but not compatible with it;
- the KEM combiner (HKDF over both shared secrets and the X25519 public values), which is in the
  style of X-Wing but not the X-Wing spec.

Nothing here is constant-time. The service logs a warning saying so when it starts in production
mode. **Do not store real card data**: the vault has not been assessed against PCI DSS.

This project has **not** had an independent security review or penetration test.
