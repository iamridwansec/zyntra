# Configuration Analysis

Zyntra's configuration analysis module examines HTTP response security settings.

## Security Headers

The module checks for:
- Content-Security-Policy
- Strict-Transport-Security
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy

It also identifies potentially weak header configurations and missing security headers.

## Cookie Security

Cookie analysis checks:
- Secure
- HttpOnly
- SameSite
- __Secure- and __Host- cookie prefix requirements

## HTTPS Behavior

The module identifies:
- The original URL scheme
- The final URL scheme
- Whether the final URL uses HTTPS
- Whether an HTTP request was redirected to HTTPS

## TLS Certificate Validation

For HTTPS targets, Zyntra performs TLS certificate verification using Python's SSL default context.

The assessment checks certificate trust and hostname verification.

The TLS result includes:
- Verification status
- Hostname and port
- Certificate subject
- Certificate issuer
- Certificate expiration information

For HTTP targets, TLS validation is skipped.

Possible TLS statuses:
- `valid`: Certificate verification succeeded.
- `invalid`: Certificate verification failed.
- `error`: A connection or TLS error occurred.
- `skipped`: The target did not use HTTPS.

## Server Information Disclosure

The module checks response headers for:
- Server
- X-Powered-By
- X-AspNet-Version
- X-Generator

## Limitations

This module does not currently perform:
- TLS protocol and cipher-suite enumeration
- Full certificate-chain reporting
- Comprehensive cookie behavior testing in a browser
- Complete evaluation of every possible security-header directive

A successful certificate verification does not guarantee that the website is secure.
