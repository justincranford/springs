package com.github.justincranford.springs.util.security.hashes.encoder.pbkdf2;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import com.github.justincranford.springs.util.basic.ArrayUtil;
import com.github.justincranford.springs.util.security.hashes.util.Asn1Util;
import com.github.justincranford.springs.util.security.hashes.util.MacAlgorithm;

@SuppressWarnings({"nls"})
public enum Pbkdf2Algorithm {
	PBKDF2WithHmacMD5       ("PBKDF2withHmacMD5",        16, MacAlgorithm.HmacMD5),
	PBKDF2WithHmacSHA1      ("PBKDF2withHmacSHA1",       20, MacAlgorithm.HmacSHA1),
	PBKDF2WithHmacSHA224    ("PBKDF2withHmacSHA224",     28, MacAlgorithm.HmacSHA224),
	PBKDF2WithHmacSHA256    ("PBKDF2withHmacSHA256",     32, MacAlgorithm.HmacSHA256),
	PBKDF2WithHmacSHA384    ("PBKDF2withHmacSHA384",     48, MacAlgorithm.HmacSHA384),
	PBKDF2WithHmacSHA512    ("PBKDF2withHmacSHA512",     64, MacAlgorithm.HmacSHA512),
	PBKDF2WithHmacSHA512_224("PBKDF2withHmacSHA512/224", 28, MacAlgorithm.HmacSHA512_224),
	PBKDF2WithHmacSHA512_256("PBKDF2withHmacSHA512/256", 32, MacAlgorithm.HmacSHA512_256),
	PBKDF2WithHmacSHA3_224  ("PBKDF2withHmacSHA3-224",   28, MacAlgorithm.HmacSHA3_224),
	PBKDF2WithHmacSHA3_256  ("PBKDF2withHmacSHA3-256",   32, MacAlgorithm.HmacSHA3_256),
	PBKDF2WithHmacSHA3_384  ("PBKDF2withHmacSHA3-384",   48, MacAlgorithm.HmacSHA3_384),
	PBKDF2WithHmacSHA3_512  ("PBKDF2withHmacSHA3-512",   64, MacAlgorithm.HmacSHA3_512),
	;

	private final String value;
	private final int bytesLen;
	private final MacAlgorithm macAlgorithm;
	private final byte[] canonicalIdBytes;
	private Pbkdf2Algorithm(final String value0, final int bytesLen0, final MacAlgorithm macAlgorithm0) {
		this.value            = value0;
		this.bytesLen         = bytesLen0;
		this.macAlgorithm     = macAlgorithm0;
		this.canonicalIdBytes = ArrayUtil.concat(Constants.PBKDF2_OID_BYTES, this.macAlgorithm.oidBytes());
	}
	public String value() {
		return this.value;
	}
	public int bytesLen() {
		return this.bytesLen;
	}
	public MacAlgorithm macAlgorithm() {
		return this.macAlgorithm;
	}
	public byte[] canonicalIdBytes() {
		return this.canonicalIdBytes;
	}

	public static class Constants {
		public static final ASN1ObjectIdentifier PBKDF2_OID       = new ASN1ObjectIdentifier("1.2.840.113549.1.5.12");
		public static final byte[]               PBKDF2_OID_BYTES = Asn1Util.oidDerBytes(PBKDF2_OID);

	}
}
