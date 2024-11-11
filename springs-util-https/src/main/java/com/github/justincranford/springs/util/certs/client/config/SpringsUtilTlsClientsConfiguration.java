package com.github.justincranford.springs.util.certs.client.config;

import javax.net.ssl.SSLContext;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.github.justincranford.springs.util.certs.server.TlsInitializer;

@Configuration
public class SpringsUtilTlsClientsConfiguration {
	@Autowired
	private SslBundles sslBundles;

	@ConditionalOnProperty(name=TlsInitializer.SslAutoConfigPropertyNames.ENABLED, matchIfMissing = false)
	@Qualifier("stlsSslContext")
	@Bean
	public SSLContext stlsSslContext() {
		final SslBundle clientSslBundle	= this.sslBundles.getBundle(TlsInitializer.SslBundleNames.CLIENT_STLS_CERT);
		return clientSslBundle.createSslContext();
	}

	@ConditionalOnProperty(name=TlsInitializer.SslAutoConfigPropertyNames.ENABLED, matchIfMissing = false)
	@Qualifier("mtlsSslContext")
	@Bean
	public SSLContext mtlsSslContext() {
		final SslBundle clientSslBundle	= this.sslBundles.getBundle(TlsInitializer.SslBundleNames.CLIENT_MTLS_CERT);
		return clientSslBundle.createSslContext();
	}

	@ConditionalOnProperty(name=TlsInitializer.SslAutoConfigPropertyNames.ENABLED, matchIfMissing = false)
	@Qualifier("ptlsSslContext")
	@Bean
	public SSLContext ptlsSslContext() {
		final SslBundle clientSslBundle	= this.sslBundles.getBundle(TlsInitializer.SslBundleNames.CLIENT_TLS_PSK);
		return clientSslBundle.createSslContext();
	}
}
