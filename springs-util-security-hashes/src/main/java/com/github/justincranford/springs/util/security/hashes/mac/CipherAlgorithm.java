package com.github.justincranford.springs.util.security.hashes.mac;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import com.github.justincranford.springs.util.basic.ArrayUtil;
import com.github.justincranford.springs.util.security.hashes.asn1.Asn1Util;

@SuppressWarnings({"nls", "hiding"})
public enum CipherAlgorithm {
	AESGCM256 ("AES/GCM/NoPadding",     true,  K.K32, I.P39, O.U,  0,  Oid.AESGCM256),
	AESGCM192 ("AES/GCM/NoPadding",     true,  K.K24, I.P39, O.U,  0,  Oid.AESGCM192),
	AESGCM128 ("AES/GCM/NoPadding",     true,  K.K16, I.P39, O.U,  0,  Oid.AESGCM128),
	AESCBC256 ("AES/CBC/PKCS5Padding",  false, K.K32, I.P39, O.U,  0,  Oid.AESCBC256),
	AESCBC192 ("AES/CBC/PKCS5Padding",  false, K.K24, I.P39, O.U,  0,  Oid.AESCBC192),
	AESCBC128 ("AES/CBC/PKCS5Padding",  false, K.K16, I.P39, O.U,  0,  Oid.AESCBC128),
	AESCMAC256("AES-CMAC",              false, K.K32, I.U,   null, 16, Oid.AESCMAC256),
	AESCMAC192("AES-CMAC",              false, K.K24, I.U,   null, 16, Oid.AESCMAC192),
	AESCMAC128("AES-CMAC",              false, K.K16, I.U,   null, 16, Oid.AESCMAC128),
	;

	private final String               algorithm;
	private final boolean              supportsAad;
	private final Set<Integer>         keyBytesLens;
	private final BigInteger           maxInputBytesLen;
	private final BigInteger           maxOutputBytesLen;
	private final int                  macOutputBytesLen;
	private final ASN1ObjectIdentifier asn1Oid;
	private final byte[]               asn1OidBytes;
	private final String               canonicalString;
	private final String               toString;
	private CipherAlgorithm(
		final String algorithm0,
		final boolean supportsAad0,
		final Set<Integer> keyBytesLens0,
		final BigInteger maxInputBytesLen0,
		final BigInteger maxOutputBytesLen0,
		final int macOutputBytesLen0,
		final ASN1ObjectIdentifier asnOid0
	) {
		this.algorithm         = algorithm0;
		this.supportsAad       = supportsAad0;
		this.keyBytesLens      = keyBytesLens0;
		this.maxInputBytesLen  = maxInputBytesLen0;
		this.maxOutputBytesLen = maxOutputBytesLen0;
		this.macOutputBytesLen = macOutputBytesLen0;
		this.asn1Oid           = asnOid0;
		this.asn1OidBytes      = Asn1Util.derBytes(asnOid0);
		this.canonicalString   = this.asn1Oid.getId();
		this.toString          = this.algorithm + "[" + this.canonicalString + "]";
	}
	public String algorithm() {
		return this.algorithm;
	}
	public boolean supportsAad() {
		return this.supportsAad;
	}
	public Set<Integer> keyBytesLens() {
		return this.keyBytesLens;
	}
	public BigInteger maxInputBytesLen() {
		return this.maxInputBytesLen;
	}
	public BigInteger maxOutputBytesLen() {
		return this.maxOutputBytesLen;
	}
	public int macOutputBytesLen() {
		return this.macOutputBytesLen;
	}
	public ASN1ObjectIdentifier asn1Oid() {
		return this.asn1Oid;
	}
	public byte[] asn1OidBytes() {
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

	public static CipherAlgorithm oidOf(final ASN1ObjectIdentifier asn1Oid) {
		return Arrays.stream(CipherAlgorithm.values())
			.filter(value -> value.asn1Oid().equals(asn1Oid))
			.findFirst()
			.orElseThrow(() -> new RuntimeException("asn1Oid not found"));
	}
	public static CipherAlgorithm canonicalString(String canonicalString) {
		return Arrays.stream(CipherAlgorithm.values())
			.filter(value -> value.canonicalString().equals(canonicalString))
			.findFirst()
			.orElseThrow(() -> new RuntimeException("canonicalString not found"));
	}

    public byte[] compute(final byte[] bytes, final byte[] aadBytes) {
		try {
			final Cipher cipher = Cipher.getInstance(this.algorithm);
			if (aadBytes != null) {
				cipher.updateAAD(aadBytes);
			}
			final byte[] enciphered = cipher.doFinal(bytes);
			return enciphered;
		} catch (NoSuchAlgorithmException | IllegalBlockSizeException | BadPaddingException | NoSuchPaddingException e) {
			throw new RuntimeException(e);
		}
	}

    public byte[] compute(final byte[][] dataChunks, final byte[] aadBytes) {
        byte[] enciphered = null;
        for (final byte[] data : dataChunks) {
            if (enciphered == null) {
                enciphered = this.compute(data, aadBytes);
            } else {
                enciphered = this.compute(ArrayUtil.concat(enciphered, data), aadBytes);
            }
        }
        return enciphered;
    }

    public static class K {
    	public static final Set<Integer> ALL  = new LinkedHashSet<>(List.of(Integer.valueOf(32), Integer.valueOf(24), Integer.valueOf(16)));
    	public static final Set<Integer> K32 = new LinkedHashSet<>(List.of(Integer.valueOf(32)));
    	public static final Set<Integer> K24 = new LinkedHashSet<>(List.of(Integer.valueOf(24)));
    	public static final Set<Integer> K16 = new LinkedHashSet<>(List.of(Integer.valueOf(16)));
    }

    public static class I {
		public static final BigInteger P39  = BigInteger.ONE.pow(39).subtract(BigInteger.valueOf(256L));
		public static final BigInteger U = BigInteger.ONE.pow(125).subtract(BigInteger.ONE); // effectively unlimited, but implementations can pick something
    }

    public static class O {
		public static final BigInteger C = BigInteger.valueOf(16L);
		public static final BigInteger U = I.U.add(BigInteger.valueOf(16L)); // effectively unlimited, but implementations can pick something
    }

    public static class Oid {
		public static final ASN1ObjectIdentifier AESGCM256  = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.1.46");
		public static final ASN1ObjectIdentifier AESGCM192  = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.1.26");
		public static final ASN1ObjectIdentifier AESGCM128  = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.1.6");

		public static final ASN1ObjectIdentifier AESCBC256  = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.1.42");
		public static final ASN1ObjectIdentifier AESCBC192  = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.1.22");
		public static final ASN1ObjectIdentifier AESCBC128  = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.1.2");

		public static final ASN1ObjectIdentifier AESCMAC256 = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.1.49");
		public static final ASN1ObjectIdentifier AESCMAC192 = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.1.29");
		public static final ASN1ObjectIdentifier AESCMAC128 = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.1.9");
    }
}
