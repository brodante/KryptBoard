package com.example.cryptolib

import java.security.SecureRandom

class ChaCha20Poly1305Stub : StreamCipher {
    private val rng = SecureRandom()

    override fun encrypt(plaintext: ByteArray, aad: ByteArray?): CipherOut {
        val nonce = ByteArray(12).also { rng.nextBytes(it) }
        val ct = Base64Url.encode(plaintext)
        return CipherOut(1, "CHACHA20-POLY1305-STUB", nonce, ct, ByteArray(0))
    }

    override fun decrypt(input: CipherOut, aad: ByteArray?): ByteArray {
        return Base64Url.decode(input.ct)
    }
}
