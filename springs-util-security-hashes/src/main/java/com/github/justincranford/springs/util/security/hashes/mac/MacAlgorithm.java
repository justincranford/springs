package com.github.justincranford.springs.util.security.hashes.mac;

import java.math.BigInteger;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import com.github.justincranford.springs.util.basic.ArrayUtil;
import com.github.justincranford.springs.util.security.hashes.digest.DigestAlgorithm;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Null;

public interface MacAlgorithm {
	public String algorithm();
	public BigInteger maxInputBytesLen();
	public int outputBytesLen();
	public ASN1ObjectIdentifier asn1Oid();
	public byte[] asn1OidBytes();
	public String canonicalString();

    public SecretKeySpec secretKeyFromDataChunks(@Null final DigestAlgorithm secretKeyDigest, @NotEmpty final byte[][] dataChunks);

    public byte[] compute(@NotNull final SecretKey key, @NotNull final byte[] data);

    default public byte[] chain(@NotNull final SecretKey key, @NotNull final byte[][] dataChunks) {
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
}
