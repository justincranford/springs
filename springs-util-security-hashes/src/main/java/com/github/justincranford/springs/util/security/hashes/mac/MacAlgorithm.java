package com.github.justincranford.springs.util.security.hashes.mac;

import java.math.BigInteger;
import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import com.github.justincranford.springs.util.basic.ArrayUtil;
import com.github.justincranford.springs.util.security.hashes.asn1.Asn1Util;
import com.github.justincranford.springs.util.security.hashes.cipher.CipherAlgorithm;
import com.github.justincranford.springs.util.security.hashes.cipher.CmacUtil;
import com.github.justincranford.springs.util.security.hashes.digest.DigestAlgorithm;

import jakarta.validation.constraints.NotNull;

@SuppressWarnings({"nls"})
public enum MacAlgorithm {
	AesCmac128    ("AesCmac128",     CipherAlgorithm.AESCMAC128, null,                     Oid.AES_CMAC_128),
	AesCmac192    ("AesCmac192",     CipherAlgorithm.AESCMAC192, null,                     Oid.AES_CMAC_192),
	AesCmac256    ("AesCmac256",     CipherAlgorithm.AESCMAC256, null,                     Oid.AES_CMAC_256),
	HmacMD5       ("HmacMD5",        null,                       DigestAlgorithm.MD5,      Oid.HMAC_MD5),
	HmacSHA1      ("HmacSHA1",       null,                       DigestAlgorithm.SHA1,     Oid.HMAC_SHA1),
	HmacSHA224    ("HmacSHA224",     null,                       DigestAlgorithm.SHA224,   Oid.HMAC_SHA224),
	HmacSHA256    ("HmacSHA256",     null,                       DigestAlgorithm.SHA256,   Oid.HMAC_SHA256),
	HmacSHA384    ("HmacSHA384",     null,                       DigestAlgorithm.SHA384,   Oid.HMAC_SHA384),
	HmacSHA512    ("HmacSHA512",     null,                       DigestAlgorithm.SHA512,   Oid.HMAC_SHA512),
	HmacSHA512_224("HmacSHA512/224", null,                       DigestAlgorithm.SHA512,   Oid.HMAC_SHA512_224),
	HmacSHA512_256("HmacSHA512/256", null,                       DigestAlgorithm.SHA512,   Oid.HMAC_SHA512_256),
	HmacSHA3_224  ("HmacSHA3-224",   null,                       DigestAlgorithm.SHA3_224, Oid.HMAC_SHA3_224),
	HmacSHA3_256  ("HmacSHA3-256",   null,                       DigestAlgorithm.SHA3_256, Oid.HMAC_SHA3_256),
	HmacSHA3_384  ("HmacSHA3-384",   null,                       DigestAlgorithm.SHA3_384, Oid.HMAC_SHA3_384),
	HmacSHA3_512  ("HmacSHA3-512",   null,                       DigestAlgorithm.SHA3_512, Oid.HMAC_SHA3_512),
	;

	private final String               algorithm;
	private final CipherAlgorithm      cipherAlgorithm;
	private final DigestAlgorithm      digestAlgorithm;
	private final BigInteger           maxInputBytesLen;
	private final int                  macOutputBytesLen;
	private final ASN1ObjectIdentifier asn1Oid;
	private final byte[]               asn1OidBytes;
	private final String               canonicalString;
	private final String               toString;
	private MacAlgorithm(final String algorithm0, final CipherAlgorithm cipherAlgorithm0, final DigestAlgorithm digestAlgorithm0, final ASN1ObjectIdentifier asn1Oid0) {
		assert (cipherAlgorithm0 == null) ^ (digestAlgorithm0 == null) : "CipherAlgorithm or DigestAlgorithm must be specified";
		this.algorithm         = algorithm0;
		this.cipherAlgorithm   = cipherAlgorithm0;
		this.digestAlgorithm   = digestAlgorithm0;
		this.maxInputBytesLen  = (digestAlgorithm0 != null) ? this.digestAlgorithm.maxInputBytesLen()     : this.cipherAlgorithm.maxInputBytesLen();
		this.macOutputBytesLen = (digestAlgorithm0 != null) ? this.digestAlgorithm.digestOutputBytesLen() : this.cipherAlgorithm.macOutputBytesLen();
		this.asn1Oid           = asn1Oid0;
		this.asn1OidBytes      = Asn1Util.derBytes(asn1Oid0);
		this.canonicalString   = asn1Oid0.getId();
		this.toString          = this.algorithm + "[" + this.canonicalString + "]";
	}
	public String algorithm() {
		return this.algorithm;
	}
	public CipherAlgorithm cipherAlgorithm() {
		return this.cipherAlgorithm;
	}
	public DigestAlgorithm digestAlgorithm() {
		return this.digestAlgorithm;
	}
	public BigInteger maxInputBytesLen() {
		return this.maxInputBytesLen;
	}
	public int outputBytesLen() {
		return this.macOutputBytesLen;
	}
	public ASN1ObjectIdentifier asn1Oid() {
		return this.asn1Oid;
	}
	public byte[] asn1OidBytes() {
		return this.asn1OidBytes;
	}
	public String canonicalString() {
		return this.canonicalString;
	}
	@Override
	public String toString() {
		return this.toString;
	}

	public static MacAlgorithm oidOf(final ASN1ObjectIdentifier asn1Oid) {
		return Arrays.stream(MacAlgorithm.values())
			.filter(value -> value.asn1Oid().equals(asn1Oid))
			.findFirst()
			.orElseThrow(() -> new RuntimeException("asn1Oid not found"));
	}
	public static MacAlgorithm canonicalStringOf(final String canonicalString) {
		return Arrays.stream(MacAlgorithm.values())
			.filter(value -> value.canonicalString().equals(canonicalString))
			.findFirst()
			.orElseThrow(() -> new RuntimeException("canonicalString not found"));
	}

	public boolean isHmac() {
		return this.digestAlgorithm != null;
	}
	public boolean isCmac() {
		return this.cipherAlgorithm != null;
	}

	public SecretKeySpec secretKeyFromDataChunks(final DigestAlgorithm cmacSecretKeyDigest, final byte[][] dataChunks) {
		final byte[] keyBytes;
		if (this.isHmac()) {
			if (cmacSecretKeyDigest != null) {
				throw new RuntimeException("DigestAlgorithm not supported for creating Hmac secretKey");
			}
			keyBytes = ArrayUtil.concat(dataChunks); // use all bytes, no need to apply digest
		} else if (this.isCmac()) {
			if (cmacSecretKeyDigest == null) {
				throw new RuntimeException("DigestAlgorithm is required for creating Cmac secretKey");
			}
			keyBytes = new byte[this.cipherAlgorithm.keyBytesLens().iterator().next().intValue()]; // use first supported keyBytes length
			final byte[] cmacDigestBytes = cmacSecretKeyDigest.compute(dataChunks); // digest chain the data chunks
			if (cmacDigestBytes.length < keyBytes.length) {
				throw new RuntimeException("Not enough digested bytes to fill Cmac secretKey");
			}
			System.arraycopy(cmacDigestBytes, 0, keyBytes, 0, keyBytes.length); // truncate to required key length
		} else {
			throw new RuntimeException("Unsupported pepper mac algorithm");
		}
		return new SecretKeySpec(keyBytes, this.algorithm);
	}

    public byte[] compute(@NotNull final SecretKey key, @NotNull final byte[] data) {
		if (this.digestAlgorithm != null) {
	        return HmacUtil.compute(this.algorithm, key, data);
		} else if (this.cipherAlgorithm != null) {
            return CmacUtil.compute(key, data);
		} else {
			throw new RuntimeException("No mac specified");
		}
    }

    public byte[] chain(@NotNull final SecretKey key, @NotNull final byte[][] dataChunks) {
        byte[] mac = null;
        for (final byte[] data : dataChunks) {
            if (mac == null) {
                mac = this.compute(key, data);
            } else {
                mac = this.compute(key, ArrayUtil.concat(mac, data));
            }
        }
        return mac;
    }

	public static class Oid {
		// See NIST cryptographic algorithms family "hash functions"
		public static final ASN1ObjectIdentifier AES_CMAC_128    = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.25");
		public static final ASN1ObjectIdentifier AES_CMAC_192    = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.26");
		public static final ASN1ObjectIdentifier AES_CMAC_256    = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.27");

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
