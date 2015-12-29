package de.mkammerer.ecc.playground

import com.google.gson.Gson
import org.whispersystems.curve25519.Curve25519
import org.whispersystems.curve25519.Curve25519KeyPair
import org.whispersystems.curve25519.Curve25519KeyPairExt
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.*
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

private val gson = Gson()

private val pairFile1 = Paths.get("pair1.key")
private val pairFile2 = Paths.get("pair2.key")

private val cipher = Curve25519.getInstance(Curve25519.BEST)

/**
 * Small playground which uses ECC with Curve25519 to agree on a shared key. Then uses SHA-256 to derive a session key
 * for AES-GCM encryption.
 *
 * This example only works with installed JCE Unlimited Strength, as AES-256 is used.
 */
fun main(args: Array<String>) {
    val pairs = loadOrGenerateKeyPairs()

    val pair1 = pairs.first
    val pair2 = pairs.second

    val agreement1 = cipher.calculateAgreement(pair2.publicKey, pair1.privateKey)
    val agreement2 = cipher.calculateAgreement(pair1.publicKey, pair2.privateKey)

    val key1 = deriveKey(agreement1)
    val key2 = deriveKey(agreement2)

    val payload = encrypt("Hello Curve25519".toByteArray(), key1)
    println("Encrypted: " + Base64.getEncoder().encodeToString(payload.data))

    val plaintext = decrypt(payload, key2)
    println("Decrypted: " + String(plaintext, Charsets.UTF_8))
}

/**
 * Encrypts the given data with the given key and returns the encrypted payload.
 */
private fun encrypt(data: ByteArray, key: ByteArray): Payload {
    val nonceLength = 16 // Bytes
    val random = SecureRandom()

    val nonce = ByteArray(nonceLength)
    random.nextBytes(nonce)

    val aes = createCipher(nonce, key, Cipher.ENCRYPT_MODE)
    val cipherText = aes.doFinal(data)

    return Payload(nonce, cipherText)
}

/**
 * Decryptes the payload with the given key and returns the plaintext.
 */
private fun decrypt(payload: Payload, key: ByteArray): ByteArray {
    val aes = createCipher(payload.nonce, key, Cipher.DECRYPT_MODE)

    return aes.doFinal(payload.data)
}

/**
 * Helper method to create a cipher.
 *
 * @param nonce the nonce
 * @param key the key
 * @param mode the cipher mode. Use [Cipher.ENCRYPT_MODE] or [Cipher.DECRYPT_MODE]
 */
private fun createCipher(nonce: ByteArray, key: ByteArray, mode: Int): Cipher {
    val tagLength = 16 // Bytes

    val spec = GCMParameterSpec(tagLength * 8, nonce)
    val aes = Cipher.getInstance("AES/GCM/NoPadding")

    aes.init(mode, SecretKeySpec(key, "AES"), spec)

    return aes
}

/**
 * Derives a key from the given agreement.
 */
private fun deriveKey(agreement: ByteArray): ByteArray {
    val sha256 = MessageDigest.getInstance("SHA-256")
    return sha256.digest(agreement)
}

/**
 * Tries to load the two key pairs. If the two keypairs don't exist, create new ones and store them on disk.
 */
private fun loadOrGenerateKeyPairs(): Pair<Curve25519KeyPair, Curve25519KeyPair> {
    return if (Files.exists(pairFile1) && Files.exists(pairFile2)) {
        Pair(loadPair(pairFile1), loadPair(pairFile2))
    } else {
        val pair1 = cipher.generateKeyPair()
        val pair2 = cipher.generateKeyPair()
        savePair(pair1, pairFile1)
        savePair(pair2, pairFile2)

        Pair(pair1, pair2)
    }
}

/**
 * Loads a key pair from the given file.
 */
private fun loadPair(file: Path): Curve25519KeyPair {
    val dto = Files.newBufferedReader(file).use {
        gson.fromJson(it, KeyPair::class.java)
    }

    return Curve25519KeyPairExt(dto.publicKey, dto.privateKey)
}

/**
 * Saves the given keypair to the given file.
 */
private fun savePair(pair: Curve25519KeyPair, file: Path) {
    val dto = KeyPair(pair.privateKey, pair.publicKey)

    Files.newBufferedWriter(file).use {
        gson.toJson(dto, it)
    }
}

/**
 * Stores a key pair.
 */
private data class KeyPair(val privateKey: ByteArray, val publicKey: ByteArray)

/**
 * Encrypted payload.
 */
private data class Payload(val nonce: ByteArray, val data: ByteArray)