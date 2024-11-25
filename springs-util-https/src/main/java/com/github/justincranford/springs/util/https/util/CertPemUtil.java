package com.github.justincranford.springs.util.https.util;

import com.github.justincranford.springs.util.basic.BasicPemUtil;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

@NoArgsConstructor(access=AccessLevel.PRIVATE)
@SuppressWarnings({"unused"})
public final class CertPemUtil {
	public static String toPems(final X509Certificate... certificates) {
		final byte[][] payloads = Arrays.stream(certificates).map(certificate -> {
			try {
				return certificate.getEncoded();
			} catch (CertificateEncodingException e) {
				throw new RuntimeException(e);
			}
		}).toArray(byte[][]::new);
		return BasicPemUtil.toPems("CERTIFICATE", payloads);
	}

	public static String toPem(final X509Certificate certificate) throws CertificateEncodingException {
		return BasicPemUtil.toPem("CERTIFICATE", certificate.getEncoded());
	}

	public static String toPem(final PrivateKey privateKey) throws IOException {
		return BasicPemUtil.toPem(
			privateKey.getAlgorithm().toUpperCase() + " PRIVATE KEY", // RSA, EC, ED, DSA, etc
			PrivateKeyInfo.getInstance(privateKey.getEncoded()).parsePrivateKey().toASN1Primitive().getEncoded()
		);
	}

	public static String toPem(final SecretKey key) {
		return BasicPemUtil.toPem("SECRET KEY", key.getEncoded()); // AES, 3DES
	}
}
