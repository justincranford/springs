package com.github.justincranford.springs.util.certs.client.config;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

import com.github.justincranford.springs.util.certs.server.TomcatTlsInitializer;

@Configuration
@SuppressWarnings({"static-method"})
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
        final SslBundle clientSslBundle = sslBundles.getBundle(TomcatTlsInitializer.SslBundleNames.CLIENT_STLS);
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
        final SslBundle clientSslBundle = sslBundles.getBundle(TomcatTlsInitializer.SslBundleNames.CLIENT_MTLS);
		return restTemplateBuilder.setSslBundle(clientSslBundle).build();
	}
}
