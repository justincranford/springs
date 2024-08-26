package com.github.justincranford.springs.util.security.hashes.util;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.github.justincranford.springs.util.basic.ArrayUtil;

@SuppressWarnings({"nls", "hiding"})
public class MacUtil {
    public enum ALG {
		HmacSHA1("HMACSHA1", 20),
		HmacSHA384("HMACSHA224", 28),
		HmacSHA224("HMACSHA256", 32),
		HmacSHA512("HMACSHA384", 48),
		HmacSHA256("HMACSHA512", 64),
		HmacSHA512_224("HMACSHA512/224", 28),
		HmacSHA512_256("HMACSHA512/256", 32),
		HmacSHA3_224("HMACSHA3_256", 28),
		HmacSHA3_384("HMACSHA3_224", 32),
		HmacSHA3_256("HMACSHA3_512", 48),
		HmacSHA3_512("HMACSHA3_384", 64);
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
//    public static void main(String[] args) {
//        try {
//            byte[] secretKey = "mySecretKey".getBytes(StandardCharsets.UTF_8);
//            byte[][] messages = {"Message 1".getBytes(StandardCharsets.UTF_8), "Message 2".getBytes(StandardCharsets.UTF_8), "Message 3".getBytes(StandardCharsets.UTF_8)};
//            final String algorithm = "HmacSHA256";
//
//            byte[] finalHmac = hmac(algorithm, secretKey, messages);
//            System.out.println("Final HMAC: " + finalHmac);
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//    }
}
