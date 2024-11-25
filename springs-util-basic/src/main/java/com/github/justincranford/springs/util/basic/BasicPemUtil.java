package com.github.justincranford.springs.util.basic;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.util.Arrays;

@NoArgsConstructor(access=AccessLevel.PRIVATE)
@SuppressWarnings({"unused"})
public final class BasicPemUtil {
    public static String toPem(final String type, final byte[] payload) {
        return "-----BEGIN " + type + "-----\n" + Base64Util.MIME76.encodeToString(payload) + "\n-----END " + type + "-----\n";
    }

    public static String toPems(final String type, final byte[]... payloads) {
        final StringBuilder stringBuilder = new StringBuilder();
        Arrays.stream(payloads).forEach(
            payload -> stringBuilder.append(toPem(type, payload))
        );
        return stringBuilder.toString();
    }
}
