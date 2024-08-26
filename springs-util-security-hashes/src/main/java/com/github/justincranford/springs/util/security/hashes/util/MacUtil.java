package com.github.justincranford.springs.util.security.hashes.util;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.github.justincranford.springs.util.basic.ArrayUtil;

@SuppressWarnings({"nls", "hiding"})
public class MacUtil {
    public enum ALG {
		HmacSHA1("HmacSHA1", 20),
		HmacSHA224("HmacSHA224", 28),
		HmacSHA256("HmacSHA256", 32),
		HmacSHA384("HmacSHA384", 48),
		HmacSHA512("HmacSHA512", 64),
		HmacSHA512_224("HmacSHA512/224", 28),
		HmacSHA512_256("HmacSHA512/256", 32),
		HmacSHA3_224("HmacSHA3-224", 28),
		HmacSHA3_256("HmacSHA3-256", 32),
		HmacSHA3_384("HmacSHA3-384", 48),
		HmacSHA3_512("HmacSHA3-512", 64);
		private final String alg;
		private final int lenBytes;
		private ALG(final String alg, final int lenBytes) {
			this.alg = alg;
			this.lenBytes = lenBytes;
		}
		public String alg() {
			return this.alg;
		}
		public int lengthBytes() {
			return this.lenBytes;
		}
	}

    public static byte[] hmac(final String algorithm, final byte[] key, final byte[] data) {
		try {
	        final Mac mac = Mac.getInstance(algorithm);
	        mac.init(new SecretKeySpec(key, algorithm));
	        return mac.doFinal(data);
		} catch (NoSuchAlgorithmException | InvalidKeyException e) {
			throw new RuntimeException(e);
		}
    }

    public static byte[] hmac(final String algorithm, final byte[] key, final byte[][] dataChunks) {
        byte[] hmac = null;
        for (final byte[] data : dataChunks) {
            if (hmac == null) {
                hmac = hmac(algorithm, key, data);
            } else {
                hmac = hmac(algorithm, key, ArrayUtil.concat(hmac, data));
            }
        }
        return hmac;
    }
}
