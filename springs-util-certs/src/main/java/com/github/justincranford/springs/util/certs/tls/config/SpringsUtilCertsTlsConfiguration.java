package com.github.justincranford.springs.util.certs.tls.config;

import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

import com.github.justincranford.springs.util.certs.tls.TomcatTlsInitializer;

@Configuration
@SuppressWarnings({"static-method"})
public class SpringsUtilCertsTlsConfiguration {
	@Bean
	public RestTemplate tlsMutualAuthenticationRestTemplate(final RestTemplateBuilder restTemplateBuilder, final SslBundles sslBundles) {
        final SslBundle clientSslBundle = sslBundles.getBundle(TomcatTlsInitializer.CLIENT_BUNDLE_MUTUAL_AUTHENTICATION);
		return restTemplateBuilder
			.setSslBundle(clientSslBundle)
			.build();
	}

	@Bean
	public RestTemplate tlsServerAuthenticationRestTemplate(final RestTemplateBuilder restTemplateBuilder, final SslBundles sslBundles) {
        final SslBundle clientSslBundle = sslBundles.getBundle(TomcatTlsInitializer.CLIENT_BUNDLE_SERVER_AUTHENTICATION);
		return restTemplateBuilder
			.setSslBundle(clientSslBundle)
			.build();
	}
}
