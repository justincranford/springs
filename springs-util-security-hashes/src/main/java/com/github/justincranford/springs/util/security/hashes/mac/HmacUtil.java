package com.github.justincranford.springs.util.security.hashes.mac;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;


public class HmacUtil {
	public static byte[] compute(final String algorithm, final SecretKey key, final byte[] data) {
		try {
			final Mac mac = Mac.getInstance(algorithm);
			mac.init(key);
			return mac.doFinal(data);
		} catch (NoSuchAlgorithmException | InvalidKeyException e) {
			throw new RuntimeException(e);
		}
	}
}

