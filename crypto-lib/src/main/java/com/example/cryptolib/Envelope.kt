package com.example.cryptolib

object Envelope {
    // Serialize as: v1|alg|nonce|ct|tag (nonce/ct/tag are base64url strings)
    fun toString(co: CipherOut): String {
        val nonce = Base64Url.encodeToString(co.nonce)
        val ct = Base64Url.encodeToString(co.ct)
        val tag = Base64Url.encodeToString(co.tag ?: ByteArray(0))
        return "v${co.version}|${co.alg}|$nonce|$ct|$tag"
    }

    fun parse(s: String): CipherOut {
        val parts = s.split("|")
        require(parts.size == 5 && parts[0].startsWith("v")) { "Invalid envelope" }
        val version = parts[0].removePrefix("v").toByte()
        val alg = parts[1]
        val nonce = Base64Url.decodeFromString(parts[2])
        val ct = Base64Url.decodeFromString(parts[3])
        val tag = Base64Url.decodeFromString(parts[4])
        return CipherOut(version, alg, nonce, ct, tag)
    }
}
