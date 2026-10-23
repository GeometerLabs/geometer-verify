# Security policy

## Reporting a vulnerability

Please report vulnerabilities through GitHub private vulnerability reporting on this repository: open the **Security** tab, choose **Report a vulnerability**, and describe the problem. Do not open a public issue for a vulnerability.

If you cannot use GitHub, write to security@geometer.dev.

Useful details: the commit or release you tested, the input (a pack, anchor, bundle or record) that triggers the problem, what you expected and what happened, and the platform.

We will acknowledge a report as soon as we can, tell you whether we consider it a vulnerability, and credit you in the fix if you wish. This is an alpha-stage project run by a small team; we do not offer a bug bounty and cannot promise a fixed response time.

## What counts

In scope for this repository:

- A pack, anchor, key log or assessment that `geo-verify` reports as verified, signed or current when it has been changed, forged or revoked.
- A crash, hang or unbounded memory use on a crafted input.
- A difference between the Rust, TypeScript and Python codecs on the same input that would let one reader accept what another refuses.
- A mistake in the signature suites (`geo-ed25519/1`, `geo-ml-dsa-65/1`) or their profiles that weakens what they are documented to give.

Out of scope here: the closed Geometer product (report that through the channel in its own documentation), the dependencies themselves (report those upstream, and tell us if the verifier is affected), and the limits written in the README. The verifier checks integrity relative to anchors and keys you supply; it does not show that a record is true or complete or who the issuer is, so "the verifier did not detect a lie in a correctly signed record" is not a vulnerability.

## Test keys

Keys and seeds in the test fixtures are published synthetic test constants. They protect nothing. Never use them for real data.
