package com.github.justincranford.springs.util.security.hashes.mac;

import com.github.justincranford.springs.util.basic.ArrayUtil;
import com.github.justincranford.springs.util.security.hashes.digest.DigestAlgorithm;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.springframework.lang.Nullable;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;

public interface MacAlgorithm {
    String algorithm();

    BigInteger maxInputBytesLen();

    int outputBytesLen();

    ASN1ObjectIdentifier asn1Oid();

    byte[] asn1OidBytes();

    String canonicalString();

    SecretKeySpec secretKeyFromDataChunks(@Nullable DigestAlgorithm secretKeyDigest, @NotEmpty final byte[][] dataChunks);

    default byte[] chain(@NotNull final SecretKey key, @NotNull final byte[][] dataChunks) {
        byte[] mac = null;
        for (final byte[] data : dataChunks) {
            if (mac == null) {
                mac = this.compute(key, data);
            } else {
                mac = this.compute(key, ArrayUtil.concat(mac, data));
            }
        }
        return mac;
    }

    byte[] compute(@NotNull final SecretKey key, @NotNull final byte[] data);
}
