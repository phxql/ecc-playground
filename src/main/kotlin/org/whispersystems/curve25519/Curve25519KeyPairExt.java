package org.whispersystems.curve25519;

/**
 * Hack to be able to create an instance of [Curve25519KeyPair]. Original constructor is package-protected.
 */
public class Curve25519KeyPairExt extends Curve25519KeyPair {
    public Curve25519KeyPairExt(byte[] publicKey, byte[] privateKey) {
        super(publicKey, privateKey);
    }
}
