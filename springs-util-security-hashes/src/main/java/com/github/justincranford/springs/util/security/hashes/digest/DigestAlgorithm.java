package com.github.justincranford.springs.util.security.hashes.digest;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import com.github.justincranford.springs.util.basic.ArrayUtil;
import com.github.justincranford.springs.util.security.hashes.asn1.Asn1Util;

@SuppressWarnings({"nls", "hiding"})
public enum DigestAlgorithm {
	MD2       ("MD2",         I.P61,  16, Oid.MD2),
	MD4       ("MD4",         I.P61,  16, Oid.MD4),
	MD5       ("MD5",         I.P61,  16, Oid.MD5),
	SHA1      ("SHA-1",       I.P61,  20, Oid.SHA1),
	SHA224    ("SHA-224",     I.P61,  28, Oid.SHA224),
	SHA256    ("SHA-256",     I.P61,  32, Oid.SHA256),
	SHA384    ("SHA-384",     I.P125, 48, Oid.SHA384),
	SHA512    ("SHA-512",     I.P125, 64, Oid.SHA512),
	SHA512_224("SHA-512/224", I.P125, 48, Oid.SHA512_224),
	SHA512_256("SHA-512/255", I.P125, 64, Oid.SHA512_256),
	SHA3_224  ("SHA3-224",    I.P61,  28, Oid.SHA3_224),
	SHA3_256  ("SHA3-256",    I.P61,  32, Oid.SHA3_256),
	SHA3_384  ("SHA3-384",    I.P61,  48, Oid.SHA3_384),
	SHA3_512  ("SHA3-512",    I.P61,  64, Oid.SHA3_512),
	SHAKE128  ("SHAKE128",    I.P61,  16, Oid.SHAKE128),
	SHAKE256  ("SHAKE256",    I.P61,  32, Oid.SHAKE256),
    BLAKE2S   ("BLAKE2S",     I.P61,  32, Oid.BLAKE2S),
    BLAKE2B   ("BLAKE2B",     I.P125, 64, Oid.BLAKE2B),
    BLAKE3_256("BLAKE3_256",  I.P125, 32, Oid.BLAKE3_256),
    BLAKE3_512("BLAKE3_512",  I.P125, 64, Oid.BLAKE3_512),
	;

	private final String               algorithm;
	private final BigInteger           maxInputBytesLen;
	private final int                  outputBytesLen;
	private final ASN1ObjectIdentifier asn1Oid;
	private final byte[]               asn1OidBytes;
	private final String               canonicalString;
	private final String               toString;
	private DigestAlgorithm(final String algorithm0, final BigInteger maxInputBytesLen0, final int outputBytesLen0, final ASN1ObjectIdentifier asnOid0) {
		this.algorithm        = algorithm0;
		this.maxInputBytesLen = maxInputBytesLen0;
		this.outputBytesLen   = outputBytesLen0;
		this.asn1Oid          = asnOid0;
		this.asn1OidBytes     = Asn1Util.derBytes(asnOid0);
		this.canonicalString  = this.asn1Oid.getId();
		this.toString         = this.algorithm + "[" + this.canonicalString + "]";
	}
	public String algorithm() {
		return this.algorithm;
	}
	public BigInteger maxInputBytesLen() {
		return this.maxInputBytesLen;
	}
	public int outputBytesLen() {
		return this.outputBytesLen;
	}
	public ASN1ObjectIdentifier asn1Oid() {
		return this.asn1Oid;
	}
	public byte[] asn1OidBytes() {
		return this.asn1OidBytes;
	}
	public byte[] canonicalBytes() {
		return this.asn1OidBytes();
	}
	public String canonicalString() {
		return this.canonicalString;
	}
	@Override
	public String toString() {
		return this.toString;
	}

	public static DigestAlgorithm oidOf(final ASN1ObjectIdentifier asn1Oid) {
		return Arrays.stream(DigestAlgorithm.values())
			.filter(value -> value.asn1Oid().equals(asn1Oid))
			.findFirst()
			.orElseThrow(() -> new RuntimeException("asn1Oid not found"));
	}
	public static DigestAlgorithm canonicalStringOf(final String canonicalString) {
		return Arrays.stream(DigestAlgorithm.values())
			.filter(value -> value.canonicalString().equals(canonicalString))
			.findFirst()
			.orElseThrow(() -> new RuntimeException("canonicalString not found"));
	}

    public byte[] compute(final byte[] bytes) {
		try {
			return MessageDigest.getInstance(this.algorithm).digest(bytes);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

    public byte[] compute(final byte[][] dataChunks) {
        byte[] messageDigest = null;
        for (final byte[] data : dataChunks) {
            if (messageDigest == null) {
                messageDigest = this.compute(data);
            } else {
                messageDigest = this.compute(ArrayUtil.concat(messageDigest, data));
            }
        }
        return messageDigest;
    }

	public static class I {
		public static final BigInteger P61  = BigInteger.ONE.pow(61).subtract(BigInteger.ONE);
		public static final BigInteger P125 = BigInteger.ONE.pow(125).subtract(BigInteger.ONE);
	}

    public static class Oid {
		public static final ASN1ObjectIdentifier MD2        = new ASN1ObjectIdentifier("1.2.840.113549.2.2");
		public static final ASN1ObjectIdentifier MD4        = new ASN1ObjectIdentifier("1.2.840.113549.2.4");
		public static final ASN1ObjectIdentifier MD5        = new ASN1ObjectIdentifier("1.2.840.113549.2.5");
		public static final ASN1ObjectIdentifier SHA1       = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1");
		public static final ASN1ObjectIdentifier SHA224     = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.2");
		public static final ASN1ObjectIdentifier SHA256     = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.3");
		public static final ASN1ObjectIdentifier SHA384     = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.4");
		public static final ASN1ObjectIdentifier SHA512     = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.5");
		public static final ASN1ObjectIdentifier SHA512_224 = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.6");
		public static final ASN1ObjectIdentifier SHA512_256 = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.7");

		public static final ASN1ObjectIdentifier SHA3_224   = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.8");
		public static final ASN1ObjectIdentifier SHA3_256   = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.9");
		public static final ASN1ObjectIdentifier SHA3_384   = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.19");
		public static final ASN1ObjectIdentifier SHA3_512   = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.11");

		public static final ASN1ObjectIdentifier SHAKE128   = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.12");
		public static final ASN1ObjectIdentifier SHAKE256   = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.13");

		public static final ASN1ObjectIdentifier BLAKE2S    = new ASN1ObjectIdentifier("1.3.6.1.4.1.1722.12.2.3.4.1.0");
		public static final ASN1ObjectIdentifier BLAKE2B    = new ASN1ObjectIdentifier("1.3.6.1.4.1.1722.12.2.3.4.1.1");
		public static final ASN1ObjectIdentifier BLAKE3_256 = new ASN1ObjectIdentifier("1.3.6.1.4.1.1722.12.2.3.4.1.2");
		public static final ASN1ObjectIdentifier BLAKE3_512 = new ASN1ObjectIdentifier("1.3.6.1.4.1.1722.12.2.3.4.1.3");
    }
}
