package com.github.justincranford.springs.util.security.hashes.mac;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import com.github.justincranford.springs.util.basic.ArrayUtil;
import com.github.justincranford.springs.util.security.hashes.asn1.Asn1Util;
import com.github.justincranford.springs.util.security.hashes.digest.DigestAlgorithm;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

@SuppressWarnings({"nls"})
public enum HmacAlgorithm implements MacAlgorithm {
	HmacMD5       ("HmacMD5",        DigestAlgorithm.MD5,      Oid.HMAC_MD5),
	HmacSHA1      ("HmacSHA1",       DigestAlgorithm.SHA1,     Oid.HMAC_SHA1),
	HmacSHA224    ("HmacSHA224",     DigestAlgorithm.SHA224,   Oid.HMAC_SHA224),
	HmacSHA256    ("HmacSHA256",     DigestAlgorithm.SHA256,   Oid.HMAC_SHA256),
	HmacSHA384    ("HmacSHA384",     DigestAlgorithm.SHA384,   Oid.HMAC_SHA384),
	HmacSHA512    ("HmacSHA512",     DigestAlgorithm.SHA512,   Oid.HMAC_SHA512),
	HmacSHA512_224("HmacSHA512/224", DigestAlgorithm.SHA512,   Oid.HMAC_SHA512_224),
	HmacSHA512_256("HmacSHA512/256", DigestAlgorithm.SHA512,   Oid.HMAC_SHA512_256),
	HmacSHA3_224  ("HmacSHA3-224",   DigestAlgorithm.SHA3_224, Oid.HMAC_SHA3_224),
	HmacSHA3_256  ("HmacSHA3-256",   DigestAlgorithm.SHA3_256, Oid.HMAC_SHA3_256),
	HmacSHA3_384  ("HmacSHA3-384",   DigestAlgorithm.SHA3_384, Oid.HMAC_SHA3_384),
	HmacSHA3_512  ("HmacSHA3-512",   DigestAlgorithm.SHA3_512, Oid.HMAC_SHA3_512),
	;

	private final String               algorithm;
	private final DigestAlgorithm      digestAlgorithm;
	private final BigInteger           maxInputBytesLen;
	private final int                  macOutputBytesLen;
	private final ASN1ObjectIdentifier asn1Oid;
	private final byte[]               asn1OidBytes;
	private final String               canonicalString;
	private final String               toString;
	private HmacAlgorithm(final String algorithm0, final DigestAlgorithm digestAlgorithm0, final ASN1ObjectIdentifier asn1Oid0) {
		this.algorithm         = algorithm0;
		this.digestAlgorithm   = digestAlgorithm0;
		this.maxInputBytesLen  = this.digestAlgorithm.maxInputBytesLen();
		this.macOutputBytesLen = this.digestAlgorithm.digestOutputBytesLen();
		this.asn1Oid           = asn1Oid0;
		this.asn1OidBytes      = Asn1Util.derBytes(asn1Oid0);
		this.canonicalString   = asn1Oid0.getId();
		this.toString          = this.algorithm + "[" + this.canonicalString + "]";
	}

	@Override
	public String algorithm() {
		return this.algorithm;
	}
	public DigestAlgorithm digestAlgorithm() {
		return this.digestAlgorithm;
	}
	@Override
	public BigInteger maxInputBytesLen() {
		return this.maxInputBytesLen;
	}
	@Override
	public int outputBytesLen() {
		return this.macOutputBytesLen;
	}
	@Override
	public ASN1ObjectIdentifier asn1Oid() {
		return this.asn1Oid;
	}
	@Override
	public byte[] asn1OidBytes() {
		return this.asn1OidBytes;
	}
	@Override
	public String canonicalString() {
		return this.canonicalString;
	}
	@Override
	public String toString() {
		return this.toString;
	}

	// TODO pass DigestAlgorithm from Pepper
	@Override
	public SecretKeySpec secretKeyFromDataChunks(@NotEmpty final byte[][] dataChunks) {
		final byte[] dataChunkBytes = ArrayUtil.concat(dataChunks);
		final byte[] hmacKeyBytes = (this.digestAlgorithm == null) ? dataChunkBytes : this.digestAlgorithm.compute(dataChunkBytes);
		return new SecretKeySpec(hmacKeyBytes, this.algorithm);
	}

	@Override
    public byte[] compute(@NotNull final SecretKey key, @NotNull final byte[] data) {
		try {
			final Mac hmac = Mac.getInstance(this.algorithm);
			hmac.init(key);
			return hmac.doFinal(data);
		} catch (NoSuchAlgorithmException | InvalidKeyException e) {
			throw new RuntimeException(e);
		}
    }

	public static HmacAlgorithm oidOf(final ASN1ObjectIdentifier asn1Oid) {
		return Arrays.stream(HmacAlgorithm.values())
			.filter(value -> value.asn1Oid().equals(asn1Oid))
			.findFirst()
			.orElseThrow(() -> new RuntimeException("asn1Oid not found"));
	}
	public static HmacAlgorithm canonicalStringOf(final String canonicalString) {
		return Arrays.stream(HmacAlgorithm.values())
			.filter(value -> value.canonicalString().equals(canonicalString))
			.findFirst()
			.orElseThrow(() -> new RuntimeException("canonicalString not found"));
	}

	public static class Oid {
		// See org.bouncycastle.asn1.nist.NistObjectIdentifiers.java for these Hmac OIDs
		public static final ASN1ObjectIdentifier HMAC_MD5        = new ASN1ObjectIdentifier("1.2.840.113549.2.5");
		public static final ASN1ObjectIdentifier HMAC_SHA1       = new ASN1ObjectIdentifier("1.2.840.113549.2.7");
		public static final ASN1ObjectIdentifier HMAC_SHA224     = new ASN1ObjectIdentifier("1.2.840.113549.2.8"); // 2.16.840.1.101.3.4.2.14
		public static final ASN1ObjectIdentifier HMAC_SHA256     = new ASN1ObjectIdentifier("1.2.840.113549.2.9"); // 2.16.840.1.101.3.4.2.15
		public static final ASN1ObjectIdentifier HMAC_SHA384     = new ASN1ObjectIdentifier("1.2.840.113549.2.10"); // 2.16.840.1.101.3.4.2.16
		public static final ASN1ObjectIdentifier HMAC_SHA512     = new ASN1ObjectIdentifier("1.2.840.113549.2.11"); // 2.16.840.1.101.3.4.2.17
		public static final ASN1ObjectIdentifier HMAC_SHA512_224 = new ASN1ObjectIdentifier("1.2.840.113549.2.12"); // 2.16.840.1.101.3.4.2.18
		public static final ASN1ObjectIdentifier HMAC_SHA512_256 = new ASN1ObjectIdentifier("1.2.840.113549.2.13"); // 2.16.840.1.101.3.4.2.19

		// See org.bouncycastle.asn1.nist.NistObjectIdentifiers.java for these HMAC OIDs
		public static final ASN1ObjectIdentifier HMAC_SHA3_224   = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.13"); // 2.16.840.1.101.3.4.2.20
		public static final ASN1ObjectIdentifier HMAC_SHA3_256   = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.14"); // 2.16.840.1.101.3.4.2.21
		public static final ASN1ObjectIdentifier HMAC_SHA3_384   = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.15"); // 2.16.840.1.101.3.4.2.22
		public static final ASN1ObjectIdentifier HMAC_SHA3_512   = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.16"); // 2.16.840.1.101.3.4.2.23
	}
}
