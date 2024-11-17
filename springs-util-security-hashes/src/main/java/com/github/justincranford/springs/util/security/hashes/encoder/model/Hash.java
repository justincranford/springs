package com.github.justincranford.springs.util.security.hashes.encoder.model;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

import java.security.MessageDigest;

public record Hash(
    @NotEmpty byte[] hashBytes // HmacSHA256 (Mac only), Cmac256 (Mac only), AES/GCM/NoPadding (Mac or Ciphertext+Mac)
) {
    public static Boolean isEqual(Hash actual, Hash expected) {
        return MessageDigest.isEqual(actual.hashBytes, expected.hashBytes);
    }

    public static String encode(@NotNull final HashInputConstants hashInputConstants, @NotNull final Hash hash) {
        return hashInputConstants.encode(hash.hashBytes);
    }

    public static Hash decode(@NotNull final HashInputConstants hashInputConstants, @NotNull final String encodedHash) {
        return new Hash(hashInputConstants.decode(encodedHash));
    }
}
