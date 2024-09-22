package com.github.justincranford.springs.util.security.hashes.mac;

import java.math.BigInteger;
import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;

import com.github.justincranford.springs.util.security.hashes.asn1.Asn1Util;
import com.github.justincranford.springs.util.security.hashes.digest.DigestAlgorithm;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

@SuppressWarnings({"nls"})
public enum CmacAlgorithm implements MacAlgorithm {
	AesCmac128("AesCmac128", DigestAlgorithm.SHA256, Oid.AES_CMAC_128, CipherAlgorithm.AESCMAC128),
	AesCmac192("AesCmac192", DigestAlgorithm.SHA256, Oid.AES_CMAC_192, CipherAlgorithm.AESCMAC192),
	AesCmac256("AesCmac256", DigestAlgorithm.SHA256, Oid.AES_CMAC_256, CipherAlgorithm.AESCMAC256),
	;

	private final String               algorithm;
	private final DigestAlgorithm      digestAlgorithm;
	private final BigInteger           maxInputBytesLen;
	private final int                  macOutputBytesLen;
	private final ASN1ObjectIdentifier asn1Oid;
	private final byte[]               asn1OidBytes;
	private final String               canonicalString;
	private final String               toString;
	private final CipherAlgorithm      cipherAlgorithm;
	private CmacAlgorithm(@NotEmpty final String algorithm0, @NotNull final DigestAlgorithm digestAlgorithm0, @NotNull final ASN1ObjectIdentifier asn1Oid0, @NotNull final CipherAlgorithm cipherAlgorithm0) {
		assert (digestAlgorithm0 != null) : "DigestAlgorithm must be specified";
		assert (cipherAlgorithm0 != null) : "CipherAlgorithm must be specified";
		this.algorithm         = algorithm0;
		this.cipherAlgorithm   = cipherAlgorithm0;
		this.digestAlgorithm   = digestAlgorithm0;
		this.maxInputBytesLen  = this.cipherAlgorithm.maxInputBytesLen();
		this.macOutputBytesLen = this.cipherAlgorithm.macOutputBytesLen();
		this.asn1Oid           = asn1Oid0;
		this.asn1OidBytes      = Asn1Util.derBytes(asn1Oid0);
		this.canonicalString   = asn1Oid0.getId();
		this.toString          = this.algorithm + "[" + this.canonicalString + "]";
	}
	@Override
	public String algorithm() {
		return this.algorithm;
	}
	public CipherAlgorithm cipherAlgorithm() {
		return this.cipherAlgorithm;
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

	@Override
    public SecretKeySpec secretKeyFromDataChunks(@NotEmpty final byte[][] dataChunks) {
		final byte[] cmacDigestBytes = this.digestAlgorithm.compute(dataChunks); // digest chain the data chunks
		final byte[] keyBytes = new byte[this.cipherAlgorithm().keyBytesLens().iterator().next().intValue()]; // use first supported keyBytes length
		if (cmacDigestBytes.length < keyBytes.length) {
			throw new RuntimeException("Not enough digested bytes to fill Cmac secretKey");
		}
		System.arraycopy(cmacDigestBytes, 0, keyBytes, 0, keyBytes.length); // truncate to required key length
		return new SecretKeySpec(keyBytes, this.algorithm());
	}

	@Override
    public byte[] compute(@NotNull final SecretKey key, @NotNull final byte[] data) {
        final CipherParameters cipherParameters = new KeyParameter(key.getEncoded());
        final Mac cmac = new CMac(AESEngine.newInstance());
        final byte[] macResult = new byte[cmac.getMacSize()];
        cmac.init(cipherParameters);
        cmac.update(data, 0, data.length);
        cmac.doFinal(macResult, 0);
        return macResult;
    }

	public static CmacAlgorithm oidOf(final ASN1ObjectIdentifier asn1Oid) {
		return Arrays.stream(CmacAlgorithm.values())
			.filter(value -> value.asn1Oid().equals(asn1Oid))
			.findFirst()
			.orElseThrow(() -> new RuntimeException("asn1Oid not found"));
	}
	public static CmacAlgorithm canonicalStringOf(final String canonicalString) {
		return Arrays.stream(CmacAlgorithm.values())
			.filter(value -> value.canonicalString().equals(canonicalString))
			.findFirst()
			.orElseThrow(() -> new RuntimeException("canonicalString not found"));
	}

	public static class Oid {
		// See NIST cryptographic algorithms family "hash functions"
		public static final ASN1ObjectIdentifier AES_CMAC_128    = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.25");
		public static final ASN1ObjectIdentifier AES_CMAC_192    = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.26");
		public static final ASN1ObjectIdentifier AES_CMAC_256    = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.27");
	}
}
