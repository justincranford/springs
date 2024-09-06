package com.github.justincranford.springs.util.security.hashes.cipher;

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import com.github.justincranford.springs.util.basic.ArrayUtil;
import com.github.justincranford.springs.util.security.hashes.asn1.Asn1Util;

@SuppressWarnings({"nls", "hiding"})
public enum CipherAlgorithm {
	AESCMAC   ("AES-CMAC", 32, Oids.AESCMAC),
	AESCMAC128("AES-CMAC", 16, Oids.AESCMAC128),
	AESCMAC192("AES-CMAC", 24, Oids.AESCMAC192),
	AESCMAC256("AES-CMAC", 32, Oids.AESCMAC256),
	AESGCM    ("AES-GCM",  32, Oids.AESGCM),
	AESGCM128 ("AES-GCM",  16, Oids.AESGCM128),
	AESGCM192 ("AES-GCM",  24, Oids.AESGCM192),
	AESGCM256 ("AES-GCM",  32, Oids.AESGCM256),
	;

	public static CipherAlgorithm canonicalString(String canonicalString) {
		return Arrays.stream(CipherAlgorithm.values())
			.filter(value -> value.canonicalString().equals(canonicalString))
			.findFirst()
			.orElseThrow(() -> new RuntimeException("canonicalString not found"));
	}

	private final String algorithm;
	private final int bytesLen;
	private final ASN1ObjectIdentifier asn1Oid;
	private final byte[] asn1OidBytes;
	private final String canonicalString;
	private final String toString;
	private CipherAlgorithm(final String algorithm0, final int bytesLen0, final ASN1ObjectIdentifier asnOid0) {
		this.algorithm       = algorithm0;
		this.bytesLen        = bytesLen0;
		this.asn1Oid         = asnOid0;
		this.asn1OidBytes    = Asn1Util.derBytes(asnOid0);
		this.canonicalString = this.asn1Oid.getId();
		this.toString        = this.algorithm + "[" + this.canonicalString + "]";
	}
	public String algorithm() {
		return this.algorithm;
	}
	public int lengthBytes() {
		return this.bytesLen;
	}
	public ASN1ObjectIdentifier asn1Oid() {
		return this.asn1Oid;
	}
	public byte[] oidDerBytes() {
		return this.asn1OidBytes;
	}
	public byte[] canonicalIdBytes() {
		return this.asn1OidBytes;
	}
	public String canonicalString() {
		return this.canonicalString;
	}
	@Override
	public String toString() {
		return this.toString;
	}

    public byte[] compute(final byte[] bytes, final byte[] aadBytes) {
		try {
			final Cipher cipher = Cipher.getInstance(this.algorithm);
			if (aadBytes != null) {
				cipher.updateAAD(aadBytes);
			}
			return cipher.doFinal(bytes);
		} catch (NoSuchAlgorithmException | IllegalBlockSizeException | BadPaddingException | NoSuchPaddingException e) {
			throw new RuntimeException(e);
		}
	}

    public byte[] compute(final byte[][] dataChunks, final byte[] aadBytes) {
        byte[] messageDigest = null;
        for (final byte[] data : dataChunks) {
            if (messageDigest == null) {
                messageDigest = this.compute(data, aadBytes);
            } else {
                messageDigest = this.compute(ArrayUtil.concat(messageDigest, data), aadBytes);
            }
        }
        return messageDigest;
    }

    public static class Oids {
		public static final ASN1ObjectIdentifier AESCMAC    = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.2");
		public static final ASN1ObjectIdentifier AESCMAC128 = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.2");
		public static final ASN1ObjectIdentifier AESCMAC192 = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.3");
		public static final ASN1ObjectIdentifier AESCMAC256 = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.4");
		public static final ASN1ObjectIdentifier AESGCM     = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.2");
		public static final ASN1ObjectIdentifier AESGCM128  = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.2");
		public static final ASN1ObjectIdentifier AESGCM192  = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.3");
		public static final ASN1ObjectIdentifier AESGCM256  = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.4");
    }
}
