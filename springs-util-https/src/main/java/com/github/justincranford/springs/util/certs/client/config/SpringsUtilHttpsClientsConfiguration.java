package com.github.justincranford.springs.util.certs.client.config;

import java.net.Socket;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.SecretKey;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.X509ExtendedKeyManager;

import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.config.TlsConfig;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.io.HttpClientConnectionManager;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.core5.http.ssl.TLS;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.apache.hc.core5.util.Timeout;
import org.bouncycastle.tls.BasicTlsPSKIdentity;
import org.bouncycastle.tls.PSKTlsClient;
import org.bouncycastle.tls.TlsPSKIdentity;
import org.bouncycastle.tls.TlsPSKIdentityManager;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundleKey;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.boot.ssl.SslStoreBundle;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.web.client.RestTemplate;

import com.github.justincranford.springs.util.basic.SecureRandomUtil;
import com.github.justincranford.springs.util.certs.server.TomcatTlsInitializer;

import ch.qos.logback.core.net.ssl.SSLContextFactoryBean;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Configuration
@SuppressWarnings({"nls", "static-method"})
public class SpringsUtilHttpsClientsConfiguration {
	/**
	 * @param restTemplateBuilder From Spring auto-configuration
	 * @param sslBundles From Spring auto-configuration
	 * @return RestTemplate instance for performing HTTP/TLS client connections with sTls (TLS Server Authentication)
	 * @see TomcatTlsInitializer#prependPropertySource
	 */
	@ConditionalOnProperty(name=TomcatTlsInitializer.SslAutoConfigPropertyNames.ENABLED, matchIfMissing = false)
	@Qualifier("stlsRestTemplate")
	@Bean
	public RestTemplate stlsRestTemplate(final RestTemplateBuilder restTemplateBuilder, final SslBundles sslBundles) {
		// lookup client sTLS bundle registered by TomcatTlsInitializer#prependPropertySource
        final SslBundle clientSslBundle = sslBundles.getBundle(TomcatTlsInitializer.SslBundleNames.CLIENT_STLS_CERT);
		return restTemplateBuilder.setSslBundle(clientSslBundle).build();
	}

	/**
	 * @param restTemplateBuilder From Spring auto-configuration
	 * @param sslBundles From Spring auto-configuration
	 * @return RestTemplate instance for performing HTTP/TLS client connections with mTls (TLS Mutual Authentication)
	 * @see TomcatTlsInitializer#prependPropertySource
	 */
	@ConditionalOnProperty(name=TomcatTlsInitializer.SslAutoConfigPropertyNames.ENABLED, matchIfMissing = false)
	@Qualifier("mtlsRestTemplate")
	@Bean
	public RestTemplate mtlsRestTemplate(final RestTemplateBuilder restTemplateBuilder, final SslBundles sslBundles) {
		// lookup client mTLS bundle registered by TomcatTlsInitializer#prependPropertySource
        final SslBundle clientSslBundle = sslBundles.getBundle(TomcatTlsInitializer.SslBundleNames.CLIENT_MTLS_CERT);
		return restTemplateBuilder.setSslBundle(clientSslBundle).build();
	}

	@SuppressWarnings("resource")
	@ConditionalOnProperty(name=TomcatTlsInitializer.SslAutoConfigPropertyNames.ENABLED, matchIfMissing = false)
	@Qualifier("ptlsRestTemplate")
	@Bean
	public RestTemplate ptlsRestTemplate(final SslBundles sslBundles) {
		final SSLContext sslContext = createPskSslContext(sslBundles.getBundle(TomcatTlsInitializer.SslBundleNames.CLIENT_TLS_PSK));
        final SSLConnectionSocketFactory sslSocketFactory = new SSLConnectionSocketFactory(sslContext);
        final HttpClientConnectionManager connectionManager = PoolingHttpClientConnectionManagerBuilder.create()
            .setSSLSocketFactory(sslSocketFactory)
            .setDefaultTlsConfig(TlsConfig.custom().setHandshakeTimeout(Timeout.ofSeconds(30)).setSupportedProtocols(TLS.V_1_3).build())
            .build();
        final HttpClient httpClient = HttpClientBuilder.create().setConnectionManager(connectionManager).build();
        final HttpComponentsClientHttpRequestFactory factory = new HttpComponentsClientHttpRequestFactory(httpClient);
        return new RestTemplate(factory);
	}

	public static SSLContext createPskSslContext(final SslBundle sslBundle) {
		try {
	        final SslStoreBundle sslStoreBundle  = sslBundle.getStores();
	        final KeyStore       keyStore        = sslStoreBundle.getKeyStore();
	        Assert.isNull(sslStoreBundle.getTrustStore(), "TLS PSK TrustStore expected to be null");
	        final SslBundleKey sslBundleKey = sslBundle.getKey();
			final String keyAlias    = sslBundleKey.getAlias();
			final char[] keyPassword = sslBundleKey.getPassword().toCharArray();
	        final SecretKey secretKey = (SecretKey) keyStore.getKey(keyAlias, keyPassword);
	        final TlsPSKIdentity pskIdentityManager = new BasicTlsPSKIdentity(keyAlias.getBytes(), secretKey.getEncoded());
			final PSKKeyManager pskKeyManager = new PSKKeyManager(pskIdentityManager.getPSKIdentity(), pskIdentityManager.getPSK());
			final SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
			sslContext.init(new KeyManager[] {pskKeyManager}, null, SecureRandomUtil.SECURE_RANDOM);
			return sslContext;
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	@RequiredArgsConstructor
	@Getter
	public static class PSKKeyManager implements KeyManager {
	    private final byte[] identity;
	    private final byte[] psk;
	}
}
