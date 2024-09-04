package com.github.justincranford.springs.util.security.hashes.mac;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import com.github.justincranford.springs.util.basic.ArrayUtil;
import com.github.justincranford.springs.util.security.hashes.asn1.Asn1Util;

import jakarta.validation.constraints.NotNull;

@SuppressWarnings({"nls"})
public enum MacAlgorithm {
	AesCmac       ("AesCmac",        16, Constants.AES_CMAC_OID),
	AesCmac128    ("AesCmac128",     16, Constants.AES_CMAC_128_OID),
	AesCmac192    ("AesCmac192",     16, Constants.AES_CMAC_192_OID),
	AesCmac256    ("AesCmac256",     16, Constants.AES_CMAC_256_OID),
	HmacMD5       ("HmacMD5",        16, Constants.HMAC_MD5_OID),
	HmacSHA1      ("HmacSHA1",       20, Constants.HMAC_SHA1_OID),
	HmacSHA224    ("HmacSHA224",     28, Constants.HMAC_SHA224_OID),
	HmacSHA256    ("HmacSHA256",     32, Constants.HMAC_SHA256_OID),
	HmacSHA384    ("HmacSHA384",     48, Constants.HMAC_SHA384_OID),
	HmacSHA512    ("HmacSHA512",     64, Constants.HMAC_SHA512_OID),
	HmacSHA512_224("HmacSHA512/224", 28, Constants.HMAC_SHA512_224_OID),
	HmacSHA512_256("HmacSHA512/256", 32, Constants.HMAC_SHA512_256_OID),
	HmacSHA3_224  ("HmacSHA3-224",   28, Constants.HMAC_SHA3_224_OID),
	HmacSHA3_256  ("HmacSHA3-256",   32, Constants.HMAC_SHA3_256_OID),
	HmacSHA3_384  ("HmacSHA3-384",   48, Constants.HMAC_SHA3_384_OID),
	HmacSHA3_512  ("HmacSHA3-512",   64, Constants.HMAC_SHA3_512_OID),
	;
	private final String value;
	private final int bytesLen;
	private final ASN1ObjectIdentifier oid;
	private final byte[] oidBytes;
	private MacAlgorithm(final String value0, final int bytesLen0, final ASN1ObjectIdentifier oid0) {
		this.value    = value0;
		this.bytesLen = bytesLen0;
		this.oid      = oid0;
		this.oidBytes = Asn1Util.oidDerBytes(oid0);
	}
	public String alg() {
		return this.value;
	}
	public int len() {
		return this.bytesLen;
	}
	public ASN1ObjectIdentifier oid() {
		return this.oid;
	}
	public byte[] oidBytes() {
		return this.oidBytes;
	}
	public byte[] canonicalIdBytes() {
		return this.oidBytes;
	}

    public byte[] compute(@NotNull final SecretKey key, @NotNull final byte[] data) {
		try {
	        final Mac mac = Mac.getInstance(this.value);
	        mac.init(key);
	        return mac.doFinal(data);
		} catch (NoSuchAlgorithmException | InvalidKeyException e) {
			throw new RuntimeException(e);
		}
    }

    public byte[] compute(@NotNull final SecretKey key, @NotNull final byte[][] dataChunks) {
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

	public static class Constants {
		// See NIST cryptographic algorithms family "hash functions"
		public static final ASN1ObjectIdentifier AES_CMAC_OID            = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.24");
		public static final ASN1ObjectIdentifier AES_CMAC_128_OID        = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.25");
		public static final ASN1ObjectIdentifier AES_CMAC_192_OID        = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.26");
		public static final ASN1ObjectIdentifier AES_CMAC_256_OID        = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.27");

		// See org.bouncycastle.asn1.nist.NistObjectIdentifiers.java for these Hmac OIDs
		public static final ASN1ObjectIdentifier HMAC_MD5_OID        = new ASN1ObjectIdentifier("1.2.840.113549.2.5");
		public static final ASN1ObjectIdentifier HMAC_SHA1_OID       = new ASN1ObjectIdentifier("1.2.840.113549.2.7");
		public static final ASN1ObjectIdentifier HMAC_SHA224_OID     = new ASN1ObjectIdentifier("1.2.840.113549.2.8"); // 2.16.840.1.101.3.4.2.14
		public static final ASN1ObjectIdentifier HMAC_SHA256_OID     = new ASN1ObjectIdentifier("1.2.840.113549.2.9"); // 2.16.840.1.101.3.4.2.15
		public static final ASN1ObjectIdentifier HMAC_SHA384_OID     = new ASN1ObjectIdentifier("1.2.840.113549.2.10"); // 2.16.840.1.101.3.4.2.16
		public static final ASN1ObjectIdentifier HMAC_SHA512_OID     = new ASN1ObjectIdentifier("1.2.840.113549.2.11"); // 2.16.840.1.101.3.4.2.17
		public static final ASN1ObjectIdentifier HMAC_SHA512_224_OID = new ASN1ObjectIdentifier("1.2.840.113549.2.12"); // 2.16.840.1.101.3.4.2.18
		public static final ASN1ObjectIdentifier HMAC_SHA512_256_OID = new ASN1ObjectIdentifier("1.2.840.113549.2.13"); // 2.16.840.1.101.3.4.2.19

		// See org.bouncycastle.asn1.nist.NistObjectIdentifiers.java for these HMAC OIDs
		public static final ASN1ObjectIdentifier HMAC_SHA3_224_OID = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.13"); // 2.16.840.1.101.3.4.2.20
		public static final ASN1ObjectIdentifier HMAC_SHA3_256_OID = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.14"); // 2.16.840.1.101.3.4.2.21
		public static final ASN1ObjectIdentifier HMAC_SHA3_384_OID = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.15"); // 2.16.840.1.101.3.4.2.22
		public static final ASN1ObjectIdentifier HMAC_SHA3_512_OID = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.16"); // 2.16.840.1.101.3.4.2.23
	}
}
