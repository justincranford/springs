package com.github.justincranford.springs.util.https.client.config;

import com.github.justincranford.springs.util.https.server.bootstrap.TlsEnabledByDefault;
import com.github.justincranford.springs.util.https.util.TlsPskUtil;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.io.HttpClientConnectionManager;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.boot.web.context.WebServerApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.http.client.JettyClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.SSLContext;

@Configuration
public class SpringsUtilHttpsClientsConfiguration {
	@Autowired
	private RestTemplateBuilder restTemplateBuilder;

	@Autowired
	private SslBundles sslBundles;

	/**
	 * @return RestTemplate instance for performing HTTP/TLS client connections with sTls (TLS Server Authentication)
	 * @see TlsEnabledByDefault#prependPropertySource
	 */
	@ConditionalOnProperty(name=TlsEnabledByDefault.SslAutoConfigPropertyNames.ENABLED)
	@Qualifier("stlsRestTemplate")
	@Bean
	public RestTemplate stlsRestTemplate() {
        final SslBundle clientSslBundle = this.sslBundles.getBundle(TlsEnabledByDefault.SslBundleNames.CLIENT_STLS_CERT);
		return this.restTemplateBuilder.setSslBundle(clientSslBundle).build();
	}

	/**
	 * @return RestTemplate instance for performing HTTP/TLS client connections with mTls (TLS Mutual Authentication)
	 * @see TlsEnabledByDefault#prependPropertySource
	 */
	@ConditionalOnProperty(name=TlsEnabledByDefault.SslAutoConfigPropertyNames.ENABLED)
	@Qualifier("mtlsRestTemplate")
	@Bean
	public RestTemplate mtlsRestTemplate() {
        final SslBundle clientSslBundle = this.sslBundles.getBundle(TlsEnabledByDefault.SslBundleNames.CLIENT_MTLS_CERT);
		return this.restTemplateBuilder.setSslBundle(clientSslBundle).build();
	}

	/**
	 * @return RestTemplate instance for performing HTTP/TLS client connections with pTls (TLS PSK Authentication)
	 * @see TlsEnabledByDefault#prependPropertySource
	 */
	@ConditionalOnProperty(name=TlsEnabledByDefault.SslAutoConfigPropertyNames.ENABLED)
	@Qualifier("ptlsRestTemplate")
	@Bean
		public RestTemplate ptlsRestTemplate(final WebServerApplicationContext webServerApplicationContext) {
		final SslBundle serverTlsPskBundle = this.sslBundles.getBundle(TlsEnabledByDefault.SslBundleNames.SERVER_TLS_PSK);
		final String webServerClassName = webServerApplicationContext.getWebServer().getClass().getName();
		if (webServerClassName.contains("Tomcat")) { // Use Apache HTTP Client
			final SSLContext                             ptlsSslContext    = serverTlsPskBundle.createSslContext();
			final SSLConnectionSocketFactory             sslSocketFactory  = new SSLConnectionSocketFactory(ptlsSslContext);
			final HttpClientConnectionManager            connectionManager = PoolingHttpClientConnectionManagerBuilder.create().setSSLSocketFactory(sslSocketFactory).build();
	        final CloseableHttpClient                    httpClient        = HttpClientBuilder.create().setConnectionManager(connectionManager).build();
	        final HttpComponentsClientHttpRequestFactory factory           = new HttpComponentsClientHttpRequestFactory(httpClient);
	        return new RestTemplate(factory);
		} else if (webServerClassName.contains("Jetty")) { // Use Jetty HTTP Client
			final SslContextFactory.Client sslContextFactory = TlsPskUtil.createClientSslContextFactory(serverTlsPskBundle);
			final HttpClient               httpClient        = new HttpClient();
			httpClient.setSslContextFactory(sslContextFactory);
	        try {
				httpClient.start();
			} catch (Exception e) {
				throw new RuntimeException("Failed to initialize Jetty HTTP Client", e);
			}
	        final JettyClientHttpRequestFactory factory = new JettyClientHttpRequestFactory(httpClient);
	        return new RestTemplate(factory);
		}
		throw new RuntimeException("Unsupported web server class: " + webServerClassName);
	}
}
