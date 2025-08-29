package com.example.cryptolib

interface StreamCipher {
    fun encrypt(plaintext: ByteArray, aad: ByteArray? = null): CipherOut
    fun decrypt(input: CipherOut, aad: ByteArray? = null): ByteArray
}
