package com.example.cryptolib

data class CipherOut(
    val version: Byte,
    val alg: String,
    val nonce: ByteArray,
    val ct: ByteArray,
    val tag: ByteArray? = null
)
