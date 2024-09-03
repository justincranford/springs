package com.github.justincranford.springs.util.security.hashes.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import com.github.justincranford.springs.util.basic.ArrayUtil;

@SuppressWarnings({"nls", "hiding"})
public class MessageDigestUtil {
    public enum ALG {
		SHA1("SHA-1", 20),
		SHA224("SHA-224", 28),
		SHA256("SHA-256", 32),
		SHA384("SHA-384", 48),
		SHA512("SHA-512", 64),
		SHA384_224("SHA-512/224", 48),
		SHA512_256("SHA-512/255", 64),
		SHA3_224("SHA3-224", 28),
		SHA3_256("SHA3-256", 32),
		SHA3_384("SHA3-384", 48),
		SHA3_512("SHA3-512", 64),
		SHA3_384_224("SHA3-512/224", 48),
		SHA3_512_256("SHA3-512/255", 64);
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

    public static byte[] messageDigest(final String algorithm, final byte[] bytes) {
		try {
			return MessageDigest.getInstance(algorithm).digest(bytes);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

    public static byte[] messageDigest(final String algorithm, final byte[][] dataChunks) {
        byte[] messageDigest = null;
        for (final byte[] data : dataChunks) {
            if (messageDigest == null) {
                messageDigest = messageDigest(algorithm, data);
            } else {
                messageDigest = messageDigest(algorithm, ArrayUtil.concat(messageDigest, data));
            }
        }
        return messageDigest;
    }

    public static class Constants {
		/**
2.16.840.1.101.3.4.2.1 - SHA-1
2.16.840.1.101.3.4.2.2 - SHA-224
2.16.840.1.101.3.4.2.3 - SHA-256
2.16.840.1.101.3.4.2.4 - SHA-384
2.16.840.1.101.3.4.2.5 - SHA-512
2.16.840.1.101.3.4.2.6 - SHA-512/224
2.16.840.1.101.3.4.2.7 - SHA-512/256
2.16.840.1.101.3.4.2.8 - SHA-3-224
2.16.840.1.101.3.4.2.9 - SHA-3-256
2.16.840.1.101.3.4.2.10 - SHA-3-384
2.16.840.1.101.3.4.2.11 - SHA-3-512
2.16.840.1.101.3.4.2.12 - SHAKE128
2.16.840.1.101.3.4.2.13 - SHAKE256
		 */
    	
    }
}
