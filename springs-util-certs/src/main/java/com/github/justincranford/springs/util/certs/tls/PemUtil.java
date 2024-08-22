package com.github.justincranford.springs.util.certs.tls;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;

import com.github.justincranford.springs.util.basic.Base64Util;

@SuppressWarnings("nls")
public class PemUtil {
	public static String toPems(final X509Certificate... certificates) {
		final byte[][] payloads = Arrays.stream(certificates).map(certificate -> {
			try {
				return certificate.getEncoded();
			} catch (CertificateEncodingException e) {
				throw new RuntimeException(e);
			}
		}).toArray(byte[][]::new);
		return toPems("CERTIFICATE", payloads);
	}

	public static String toPem(final X509Certificate certificate) throws CertificateEncodingException {
		return toPem("CERTIFICATE", certificate.getEncoded());
	}

	public static String toPem(final PrivateKey privateKey) throws IOException {
		return toPem(
			privateKey.getAlgorithm().toUpperCase() + " PRIVATE KEY", // RSA, EC, ED, DSA, etc
			PrivateKeyInfo.getInstance(privateKey.getEncoded()).parsePrivateKey().toASN1Primitive().getEncoded()
		);
	}

	private static String toPem(final String type, final byte[] payload) {
        final StringBuilder stringBuilder = new StringBuilder();
		stringBuilder.append("-----BEGIN ").append(type).append("-----\n");
		stringBuilder.append(Base64Util.MIME76_ENCODE.string(payload));
		stringBuilder.append("\n-----END ").append(type).append("-----\n");
        return stringBuilder.toString();
	}

	private static String toPems(final String type, final byte[]... payloads) {
        final StringBuilder stringBuilder = new StringBuilder();
        Arrays.stream(payloads).forEach(
    		payload -> stringBuilder.append(toPem(type, payload))
		);
        return stringBuilder.toString();
    }
}
