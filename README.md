# ECC Playground

Small playground which uses ECC with Curve25519 to agree on a shared key. Then uses SHA-256 to derive a session key
for AES-GCM encryption.

This example only works with installed JCE Unlimited Strength, as AES-256 is used.

## License

GPLv3: https://www.gnu.org/licenses/gpl-3.0.html