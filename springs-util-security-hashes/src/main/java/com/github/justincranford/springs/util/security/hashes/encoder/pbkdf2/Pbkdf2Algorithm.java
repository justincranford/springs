package com.github.justincranford.springs.util.security.hashes.encoder.pbkdf2;

import java.nio.charset.StandardCharsets;

@SuppressWarnings({"nls"})
public enum Pbkdf2Algorithm {
	PBKDF2WithHmacMD5       ("PBKDF2withHmacMD5",        16, "PBKDF2withHmacMD5"),
	PBKDF2WithHmacSHA1      ("PBKDF2withHmacSHA1",       20, "PBKDF2withHmacSHA1"),
	PBKDF2WithHmacSHA224    ("PBKDF2withHmacSHA224",     28, "PBKDF2withHmacSHA224"),
	PBKDF2WithHmacSHA256    ("PBKDF2withHmacSHA256",     32, "PBKDF2withHmacSHA256"),
	PBKDF2WithHmacSHA384    ("PBKDF2withHmacSHA384",     48, "PBKDF2withHmacSHA384"),
	PBKDF2WithHmacSHA512    ("PBKDF2withHmacSHA512",     64, "PBKDF2withHmacSHA512"),
	PBKDF2WithHmacSHA512_224("PBKDF2withHmacSHA512/224", 28, "PBKDF2withHmacSHA512/224"),
	PBKDF2WithHmacSHA512_256("PBKDF2withHmacSHA512/256", 32, "PBKDF2withHmacSHA512/256"),
	PBKDF2WithHmacSHA3_224  ("PBKDF2withHmacSHA3-224",   28, "PBKDF2withHmacSHA3-224"),
	PBKDF2WithHmacSHA3_256  ("PBKDF2withHmacSHA3-256",   32, "PBKDF2withHmacSHA3-256"),
	PBKDF2WithHmacSHA3_384  ("PBKDF2withHmacSHA3-384",   48, "PBKDF2withHmacSHA3-384"),
	PBKDF2WithHmacSHA3_512  ("PBKDF2withHmacSHA3-512",   64, "PBKDF2withHmacSHA3-512"),
	;
	private final String value;
	private final int bytesLen;
	private final byte[] canonicalEncodeBytes;
	private Pbkdf2Algorithm(final String algorithm, final int lenBytes, final String canonicalEncode) {
		this.value = algorithm;
		this.bytesLen = lenBytes;
		this.canonicalEncodeBytes = canonicalEncode.getBytes(StandardCharsets.UTF_8);
	}
	public String value() {
		return this.value;
	}
	public int bytesLen() {
		return this.bytesLen;
	}
	public byte[] canonicalEncode() {
		return this.canonicalEncodeBytes;
	}
}
