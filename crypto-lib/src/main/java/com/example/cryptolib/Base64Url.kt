package com.example.cryptolib

import java.util.Base64

object Base64Url {
    fun encode(bytes: ByteArray): ByteArray =
        Base64.getUrlEncoder().withoutPadding().encode(bytes)

    fun decode(bytes: ByteArray): ByteArray =
        Base64.getUrlDecoder().decode(bytes)

    fun encodeToString(bytes: ByteArray): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

    fun decodeFromString(s: String): ByteArray =
        Base64.getUrlDecoder().decode(s)
}
