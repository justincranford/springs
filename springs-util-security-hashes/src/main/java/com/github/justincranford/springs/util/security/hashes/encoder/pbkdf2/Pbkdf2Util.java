package com.github.justincranford.springs.util.security.hashes.encoder.pbkdf2;

@SuppressWarnings({"nls", "hiding"})
public class Pbkdf2Util {
    public enum ALG {
		PBKDF2WithHmacSHA1("PBKDF2withHmacSHA1", 20),
		PBKDF2WithHmacSHA224("PBKDF2withHmacSHA224", 28),
		PBKDF2WithHmacSHA256("PBKDF2withHmacSHA256", 32),
		PBKDF2WithHmacSHA384("PBKDF2withHmacSHA384", 48),
		PBKDF2WithHmacSHA512("PBKDF2withHmacSHA512", 64),
		PBKDF2WithHmacSHA512_224("PBKDF2withHmacSHA512/224", 28),
		PBKDF2WithHmacSHA512_256("PBKDF2withHmacSHA512/256", 32),
		PBKDF2WithHmacSHA3_224("PBKDF2withHmacSHA3-224", 28),
		PBKDF2WithHmacSHA3_256("PBKDF2withHmacSHA3-256", 32),
		PBKDF2WithHmacSHA3_384("PBKDF2withHmacSHA3-384", 48),
		PBKDF2WithHmacSHA3_512("PBKDF2withHmacSHA3-512", 64),		;
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
}
