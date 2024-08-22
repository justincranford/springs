package com.github.justincranford.springs.util.security.hashes.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class MessageDigestUtil {
	public static byte[] messageDigest(final String algorithm, final byte[] bytes) {
		try {
			return MessageDigest.getInstance(algorithm).digest(bytes);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}
}
