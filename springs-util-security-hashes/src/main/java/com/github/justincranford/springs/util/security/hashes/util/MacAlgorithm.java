package com.github.justincranford.springs.util.security.hashes.util;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;

import com.github.justincranford.springs.util.basic.ArrayUtil;

import jakarta.validation.constraints.NotNull;

@SuppressWarnings({"nls"})
public enum MacAlgorithm {
	CMAC128       ("CMAC",           16, "CMAC128"), // TODO
	CMAC192       ("CMAC",           24, "CMAC192"), // TODO
	CMAC256       ("CMAC",           32, "CMAC256"), // TODO
	HmacMD5       ("HmacMD5",        16, "HmacMD5"),
	HmacSHA1      ("HmacSHA1",       20, "HmacSHA1"),
	HmacSHA224    ("HmacSHA224",     28, "HmacSHA224"),
	HmacSHA256    ("HmacSHA256",     32, "HmacSHA256"),
	HmacSHA384    ("HmacSHA384",     48, "HmacSHA384"),
	HmacSHA512    ("HmacSHA512",     64, "HmacSHA512"),
	HmacSHA512_224("HmacSHA512/224", 28, "HmacSHA512_224"),
	HmacSHA512_256("HmacSHA512/256", 32, "HmacSHA512_256"),
	HmacSHA3_224  ("HmacSHA3-224",   28, "HmacSHA3_224"),
	HmacSHA3_256  ("HmacSHA3-256",   32, "HmacSHA3_256"),
	HmacSHA3_384  ("HmacSHA3-384",   48, "HmacSHA3_384"),
	HmacSHA3_512  ("HmacSHA3-512",   64, "HmacSHA3_512");
	private final String algorithm;
	private final int bytesLen;
	private final byte[] canonicalIdBytes;
	private MacAlgorithm(final String algorithm0, final int bytesLen0, final String canonicalId) {
		this.algorithm        = algorithm0;
		this.bytesLen         = bytesLen0;
		this.canonicalIdBytes = canonicalId.getBytes(StandardCharsets.UTF_8);
	}
	public String alg() {
		return this.algorithm;
	}
	public int len() {
		return this.bytesLen;
	}
	public byte[] canonicalIdBytes() {
		return this.canonicalIdBytes;
	}

    public byte[] compute(@NotNull final SecretKey key, @NotNull final byte[] data) {
		try {
	        final Mac mac = Mac.getInstance(this.algorithm);
	        mac.init(key);
	        return mac.doFinal(data);
		} catch (NoSuchAlgorithmException | InvalidKeyException e) {
			throw new RuntimeException(e);
		}
    }

    public byte[] compute(@NotNull final SecretKey key, @NotNull final byte[][] dataChunks) {
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
