package com.github.justincranford.springs.util.certs.tls;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;
import java.util.stream.IntStream;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.springframework.boot.autoconfigure.ssl.PemSslBundleProperties;
import org.springframework.boot.autoconfigure.ssl.PropertiesSslBundle;
import org.springframework.boot.ssl.SslBundle;

import com.github.justincranford.springs.util.basic.util.SecureRandomUtil;
import com.google.common.collect.Sets;

@SuppressWarnings("nls")
public class TlsUtil {
    // Mozilla recommended "intermediate" ciphersuites (January 2023)
	private static final Set<String> PROTOCOLS_TLS13  = Sets.newLinkedHashSet(List.of("TLSv1.3"));
//    private static final Set<String> PROTOCOLS_TLS12  = Sets.newLinkedHashSet(List.of("TLSv1.2"));
//    private static final Set<String> PROTOCOLS_TLS13_TLS12 = Sets.newLinkedHashSet(List.of("TLSv1.3", "TLSv1.2"));
//    private static final Set<String> CIPHERS_TLS13 = Sets.newLinkedHashSet(List.of("TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"));
//    private static final Set<String> CIPHERS_TLS12 = Sets.newLinkedHashSet(List.of("ECDHE-ECDSA-CHACHA20-POLY1305", "ECDHE-RSA-CHACHA20-POLY1305", "ECDHE-ECDSA-AES256-GCM-SHA384", "ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-RSA-AES128-GCM-SHA256", "DHE-RSA-AES256-GCM-SHA384", "DHE-RSA-AES128-GCM-SHA256"));
//    private static final Set<String> CIPHERS_TLS13_TLS12 = Sets.newLinkedHashSet(Stream.concat(CIPHERS_TLS13.stream(), CIPHERS_TLS12.stream()).toList());

    public static SslBundle createBundle(final String truststoreCertPem, final String keystoreCertPem, final String keystorePrivateKeyPem) throws Exception {
		final PemSslBundleProperties pemSslBundleProperties = new PemSslBundleProperties();
		pemSslBundleProperties.getOptions().setEnabledProtocols(PROTOCOLS_TLS13);
//		pemSslBundleProperties.getOptions().setCiphers(CIPHERS_TLS13_TLS12);
		pemSslBundleProperties.getTruststore().setCertificate(truststoreCertPem);
		pemSslBundleProperties.getKeystore().setCertificate(keystoreCertPem);
		pemSslBundleProperties.getKeystore().setPrivateKey(keystorePrivateKeyPem);
		return PropertiesSslBundle.get(pemSslBundleProperties);
	}

	public static SSLContext clientSslContextTlsServerAuthn(final X509Certificate... trustedCertificates) throws Exception {
		final KeyStore trustStore = createTrustStore(trustedCertificates);
		final TrustManager[] trustManagers = createTrustManagers(trustStore);
		return sslContext(null, trustManagers);
	}

	private static SSLContext sslContext(final KeyManager[] keyManagers, final TrustManager[] trustManagers) throws Exception {
		final SSLContext sslContext = SSLContext.getInstance("TLSv1.3", "SunJSSE");
		sslContext.init(keyManagers, trustManagers, SecureRandomUtil.SECURE_RANDOM);
		return sslContext;
	}

	private static TrustManager[] createTrustManagers(final KeyStore trustStore) throws Exception {
		final TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("PKIX", "SunJSSE");
		trustManagerFactory.init(trustStore);
		return trustManagerFactory.getTrustManagers();
	}

	private static KeyStore createTrustStore(final X509Certificate... trustedCertificates) throws Exception {
		final KeyStore trustStore = KeyStore.getInstance("PKCS12", "SunJSSE");
		trustStore.load(null,  null);
		IntStream.range(0, trustedCertificates.length).forEach(i -> {
			try {
				trustStore.setCertificateEntry("trusted_cert_" + i, trustedCertificates[i]);
			} catch (KeyStoreException e) {
				throw new RuntimeException(e);
			}
		});
		return trustStore;
	}
}
