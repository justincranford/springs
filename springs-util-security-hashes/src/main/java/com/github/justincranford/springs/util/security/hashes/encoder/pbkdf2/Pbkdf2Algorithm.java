package com.github.justincranford.springs.util.security.hashes.encoder.pbkdf2;

import java.util.Arrays;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;

import com.github.justincranford.springs.util.security.hashes.asn1.Asn1Util;
import com.github.justincranford.springs.util.security.hashes.mac.MacAlgorithm;

@SuppressWarnings({"nls"})
public enum Pbkdf2Algorithm {
	PBKDF2WithHmacMD5       ("PBKDF2withHmacMD5",        MacAlgorithm.HmacMD5),
	PBKDF2WithHmacSHA1      ("PBKDF2withHmacSHA1",       MacAlgorithm.HmacSHA1),
	PBKDF2WithHmacSHA224    ("PBKDF2withHmacSHA224",     MacAlgorithm.HmacSHA224),
	PBKDF2WithHmacSHA256    ("PBKDF2withHmacSHA256",     MacAlgorithm.HmacSHA256),
	PBKDF2WithHmacSHA384    ("PBKDF2withHmacSHA384",     MacAlgorithm.HmacSHA384),
	PBKDF2WithHmacSHA512    ("PBKDF2withHmacSHA512",     MacAlgorithm.HmacSHA512),
	PBKDF2WithHmacSHA512_224("PBKDF2withHmacSHA512/224", MacAlgorithm.HmacSHA512_224),
	PBKDF2WithHmacSHA512_256("PBKDF2withHmacSHA512/256", MacAlgorithm.HmacSHA512_256),
	PBKDF2WithHmacSHA3_224  ("PBKDF2withHmacSHA3-224",   MacAlgorithm.HmacSHA3_224),
	PBKDF2WithHmacSHA3_256  ("PBKDF2withHmacSHA3-256",   MacAlgorithm.HmacSHA3_256),
	PBKDF2WithHmacSHA3_384  ("PBKDF2withHmacSHA3-384",   MacAlgorithm.HmacSHA3_384),
	PBKDF2WithHmacSHA3_512  ("PBKDF2withHmacSHA3-512",   MacAlgorithm.HmacSHA3_512),
	;

	public static Pbkdf2Algorithm canonicalString(String canonicalString) {
		return Arrays.stream(Pbkdf2Algorithm.values())
			.filter(value -> value.canonicalString().equals(canonicalString))
			.findFirst()
			.orElseThrow(() -> new RuntimeException("canonicalString not found"));
	}

	private final String algorithm;
	private final MacAlgorithm macAlgorithm;
	private final DERSequence asn1DerSequence;
	private final byte[] asn1DerBytes;
	private final String canonicalString;
	private final String toString;
	private Pbkdf2Algorithm(final String algorithm0, final MacAlgorithm macAlgorithm0) {
		this.algorithm       = algorithm0;
		this.macAlgorithm    = macAlgorithm0;
		this.asn1DerSequence = Asn1Util.derSequence(Constants.PBKDF2_OID, this.macAlgorithm.asn1Oid());
		this.asn1DerBytes    = Asn1Util.derBytes(this.asn1DerSequence);
		this.canonicalString = Constants.PBKDF2_OID.getId() + "," + this.macAlgorithm.asn1Oid().getId();
		this.toString        = this.algorithm + "[" + this.canonicalString + "]";
	}
	public String algorithm() {
		return this.algorithm;
	}
	public int bytesLen() {
		return this.macAlgorithm.bytesLen();
	}
	public MacAlgorithm macAlgorithm() {
		return this.macAlgorithm;
	}
	public DERSequence asn1DerSequence() {
		return this.asn1DerSequence;
	}
	public byte[] asn1DerBytes() {
		return this.asn1DerBytes;
	}
	public String canonicalString() {
		return this.canonicalString;
	}
	@Override
	public String toString() {
		return this.toString;
	}

	public static class Constants {
		public static final ASN1ObjectIdentifier PBKDF2_OID = new ASN1ObjectIdentifier("1.2.840.113549.1.5.12");
	}
}
