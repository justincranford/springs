package com.github.justincranford.springs.util.https.util;

import com.github.justincranford.springs.util.basic.Base64Util;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

@SuppressWarnings({"unused"})
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

    private static String toPems(final String type, final byte[]... payloads) {
        final StringBuilder stringBuilder = new StringBuilder();
        Arrays.stream(payloads).forEach(
            payload -> stringBuilder.append(toPem(type, payload))
        );
        return stringBuilder.toString();
    }

    private static String toPem(final String type, final byte[] payload) {
        return "-----BEGIN " + type + "-----\n" +
               Base64Util.MIME76.encodeToString(payload) +
               "\n-----END " + type + "-----\n";
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

    public static String toPem(final SecretKey key) {
        return toPem("SECRET KEY", key.getEncoded()); // AES, 3DES
    }
}
