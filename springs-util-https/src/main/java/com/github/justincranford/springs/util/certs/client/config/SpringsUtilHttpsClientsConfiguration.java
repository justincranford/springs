package com.github.justincranford.springs.util.certs.client.config;

import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.http.client.JettyClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import com.github.justincranford.springs.util.certs.server.TlsInitializer;
import com.github.justincranford.springs.util.certs.util.TlsPskUtil;

@Configuration
@SuppressWarnings({"nls", "static-method"})
public class SpringsUtilHttpsClientsConfiguration {
	/**
	 * @param restTemplateBuilder From Spring auto-configuration
	 * @param sslBundles From Spring auto-configuration
	 * @return RestTemplate instance for performing HTTP/TLS client connections with sTls (TLS Server Authentication)
	 * @see TlsInitializer#prependPropertySource
	 */
	@ConditionalOnProperty(name=TlsInitializer.SslAutoConfigPropertyNames.ENABLED, matchIfMissing = false)
	@Qualifier("stlsRestTemplate")
	@Bean
	public RestTemplate stlsRestTemplate(final RestTemplateBuilder restTemplateBuilder, final SslBundles sslBundles) {
		// lookup client sTLS bundle registered by TlsInitializer#prependPropertySource
        final SslBundle clientSslBundle = sslBundles.getBundle(TlsInitializer.SslBundleNames.CLIENT_STLS_CERT);
		return restTemplateBuilder.setSslBundle(clientSslBundle).build();
	}

	/**
	 * @param restTemplateBuilder From Spring auto-configuration
	 * @param sslBundles From Spring auto-configuration
	 * @return RestTemplate instance for performing HTTP/TLS client connections with mTls (TLS Mutual Authentication)
	 * @see TlsInitializer#prependPropertySource
	 */
	@ConditionalOnProperty(name=TlsInitializer.SslAutoConfigPropertyNames.ENABLED, matchIfMissing = false)
	@Qualifier("mtlsRestTemplate")
	@Bean
	public RestTemplate mtlsRestTemplate(final RestTemplateBuilder restTemplateBuilder, final SslBundles sslBundles) {
		// lookup client mTLS bundle registered by TlsInitializer#prependPropertySource
        final SslBundle clientSslBundle = sslBundles.getBundle(TlsInitializer.SslBundleNames.CLIENT_MTLS_CERT);
		return restTemplateBuilder.setSslBundle(clientSslBundle).build();
	}

	@SuppressWarnings("resource")
	@ConditionalOnProperty(name=TlsInitializer.SslAutoConfigPropertyNames.ENABLED, matchIfMissing = false)
	@Qualifier("ptlsRestTemplate")
	@Bean
	public RestTemplate ptlsRestTemplate(final SslBundles sslBundles) {
		final SslBundle                  serverTlsPskBundle = sslBundles.getBundle(TlsInitializer.SslBundleNames.SERVER_TLS_PSK);
		final SslContextFactory.Client   sslContextFactory  = TlsPskUtil.createClientSslContextFactory(serverTlsPskBundle);

		// Apache HTTP Client
//		final SSLConnectionSocketFactory sslSocketFactory   = new SSLConnectionSocketFactory(sslContextFactory.getSslContext());
//		final HttpClientConnectionManager connectionManager = PoolingHttpClientConnectionManagerBuilder.create()
//            .setSSLSocketFactory(sslSocketFactory)
//            .build();
//        final HttpClient httpClient = HttpClientBuilder.create().setConnectionManager(connectionManager).build();
//        final HttpComponentsClientHttpRequestFactory factory = new HttpComponentsClientHttpRequestFactory(httpClient);

		// Jetty HTTP Client
		HttpClient httpClient = new HttpClient();
		httpClient.setSslContextFactory(sslContextFactory);
        try {
			httpClient.start();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}

        final JettyClientHttpRequestFactory factory = new JettyClientHttpRequestFactory(httpClient);
        return new RestTemplate(factory);
	}
}
