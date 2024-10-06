package com.github.justincranford.springs.util.certs.server;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Future;

import org.springframework.boot.env.OriginTrackedMapPropertySource;
import org.springframework.boot.web.server.Ssl.ClientAuth;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.env.MutablePropertySources;
import org.springframework.core.env.PropertySource;

import com.github.justincranford.springs.util.basic.ThreadUtil;
import com.github.justincranford.springs.util.certs.util.CertUtil;
import com.github.justincranford.springs.util.certs.util.KeyGenUtil;
import com.github.justincranford.springs.util.certs.util.PemUtil;
import com.github.justincranford.springs.util.certs.util.SignUtil;
import com.google.common.collect.Lists;
import com.google.common.net.InetAddresses;
import com.google.common.net.InternetDomainName;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@SuppressWarnings({"nls", "static-method"})
public class TomcatTlsInitializer implements ApplicationContextInitializer<ConfigurableApplicationContext> {
    @Override
    public void initialize(final ConfigurableApplicationContext configurableApplicationContext) {
		try {
			// Used for auto-configuration properties lookup, and prepending a new property source containing 3 dynamically created SSL bundles
	        final MutablePropertySources readWritePropertySources = configurableApplicationContext.getEnvironment().getPropertySources();

	        // ConfigurationProperties is not autowired yet, so walk through PropertySources and get SslAutoConfigProperties
	        final Collection<PropertySource<?>> readOnlyPropertySources    = Lists.newArrayList(readWritePropertySources.iterator());
			final SslAutoConfigProperties       sslAutoConfigProperties    = SslAutoConfigProperties.find(readOnlyPropertySources);
			final Boolean                       sslAutoConfigEnabled       = sslAutoConfigProperties.enabled();
			final String                        sslAutoConfigAlgorithm     = sslAutoConfigProperties.algorithm();
			final String                        sslAutoConfigServerAddress = sslAutoConfigProperties.serverAddress();
			final String                        sslAutoConfigClientEmail   = sslAutoConfigProperties.clientEmail();
			if (!sslAutoConfigEnabled.booleanValue()) {
				log.info("SSL Auto Config disabled");
				return;
			}
			log.info("SSL Auto Config enabled, algorithm: {}, serverAddress: {}, clientEmail: {}", sslAutoConfigAlgorithm, sslAutoConfigServerAddress, sslAutoConfigClientEmail);

			final List<KeyPair> keyPairs = new LinkedList<>(KeyGenUtil.generateKeyPairs(4, sslAutoConfigAlgorithm));
	        final KeyPair httpsServerRootCaKeyPair = keyPairs.removeFirst();
	        final KeyPair httpsServerKeyPair       = keyPairs.removeFirst();
	        final KeyPair httpsClientRootCaKeyPair = keyPairs.removeFirst();
	        final KeyPair httpsClientKeyPair       = keyPairs.removeFirst();

			final Future<X509Certificate> futureHttpsServerRootCaCert = ThreadUtil.async(() -> httpsServerRootCaCert(httpsServerRootCaKeyPair));
			final Future<X509Certificate> futureHttpsServerCert       = ThreadUtil.async(() -> httpsServerCert(httpsServerRootCaKeyPair.getPrivate(), httpsServerKeyPair.getPublic(), sslAutoConfigServerAddress));
			final Future<X509Certificate> futureHttpsClientRootCaCert = ThreadUtil.async(() -> httpsClientRootCaCert(httpsClientRootCaKeyPair));
			final Future<X509Certificate> futureHttpsClientCert       = ThreadUtil.async(() -> httpsClientCert(httpsClientRootCaKeyPair.getPrivate(), httpsClientKeyPair.getPublic(), sslAutoConfigClientEmail));

			final X509Certificate httpsServerRootCaCert = futureHttpsServerRootCaCert.get();
			final X509Certificate httpsServerCert       = futureHttpsServerCert.get();
			final X509Certificate httpsClientRootCaCert = futureHttpsClientRootCaCert.get();
			final X509Certificate httpsClientCert       = futureHttpsClientCert.get();

			httpsServerRootCaCert.verify(httpsServerRootCaKeyPair.getPublic());
			httpsServerCert.verify(httpsServerRootCaKeyPair.getPublic());
			httpsClientRootCaCert.verify(httpsClientRootCaKeyPair.getPublic());	
			httpsClientCert.verify(httpsClientRootCaKeyPair.getPublic());

			final String httpsServerRootCaCertPem       = PemUtil.toPem(httpsServerRootCaCert);
			final String httpsServerRootCaPrivateKeyPem = PemUtil.toPem(httpsServerRootCaKeyPair.getPrivate());
			final String httpsServerCertPem             = PemUtil.toPem(httpsServerCert);
			final String httpsServerPrivateKeyPem       = PemUtil.toPem(httpsServerKeyPair.getPrivate());
			final String httpsClientRootCaCertPem       = PemUtil.toPem(httpsClientRootCaCert);
			final String httpsClientRootCaPrivateKeyPem = PemUtil.toPem(httpsClientRootCaKeyPair.getPrivate());
			final String httpsClientCertPem             = PemUtil.toPem(httpsClientCert);
			final String httpsClientPrivateKeyPem       = PemUtil.toPem(httpsClientKeyPair.getPrivate());

			log.info("HTTPS Server Root CA:\n{}{}", httpsServerRootCaCertPem, log.isTraceEnabled() ? httpsServerRootCaPrivateKeyPem : "");
			log.info("HTTPS Server:\n{}{}",         httpsServerCertPem,       log.isTraceEnabled() ? httpsServerPrivateKeyPem       : "");
			log.info("HTTPS Client Root CA:\n{}{}", httpsClientRootCaCertPem, log.isTraceEnabled() ? httpsClientRootCaPrivateKeyPem : "");
			log.info("HTTPS Client:\n{}{}",         httpsClientCertPem,       log.isTraceEnabled() ? httpsClientPrivateKeyPem       : "");

	        prependPropertySource(readWritePropertySources, httpsServerRootCaCertPem, httpsServerCertPem,
					httpsServerPrivateKeyPem, httpsClientRootCaCertPem, httpsClientCertPem, httpsClientPrivateKeyPem);
		} catch(Exception e) {
			throw new RuntimeException(e);
		}
    }

	private void prependPropertySource(
		final MutablePropertySources mutablePropertySources,
		final String httpsServerRootCaCertPem, final String httpsServerCertPem, final String httpsServerPrivateKeyPem,
		final String httpsClientRootCaCertPem, final String httpsClientCertPem, final String httpsClientPrivateKeyPem
	) {
		// properties map containing 3 SSL bundles and helper properties
		final Map<String, Object> tlsProperties = new LinkedHashMap<>();

		// Client Bundle for performing HTTP/TLS Server Authentication
		tlsProperties.put("spring.ssl.bundle.pem." + SslBundleNames.CLIENT_STLS + ".truststore.certificate", httpsServerRootCaCertPem);

		// Client Bundle for performing HTTP/TLS Mutual Authentication
		tlsProperties.put("spring.ssl.bundle.pem." + SslBundleNames.CLIENT_MTLS + ".keystore.certificate",   httpsClientCertPem);
		tlsProperties.put("spring.ssl.bundle.pem." + SslBundleNames.CLIENT_MTLS + ".keystore.privateKey",    httpsClientPrivateKeyPem);
		tlsProperties.put("spring.ssl.bundle.pem." + SslBundleNames.CLIENT_MTLS + ".truststore.certificate", httpsServerRootCaCertPem);

		// Server Bundle for listening to HTTP/TLS client requests
		tlsProperties.put("spring.ssl.bundle.pem." + SslBundleNames.SERVER_TLS + ".keystore.certificate",   httpsServerCertPem);
		tlsProperties.put("spring.ssl.bundle.pem." + SslBundleNames.SERVER_TLS + ".keystore.privateKey",    httpsServerPrivateKeyPem);
		tlsProperties.put("spring.ssl.bundle.pem." + SslBundleNames.SERVER_TLS + ".truststore.certificate", httpsClientRootCaCertPem);

		// Server HTTP/TLS configuration to enable TLS, use the server bundle, and accept clients performing sTLS or mTLS
		tlsProperties.put("server.ssl.enabled",          Boolean.TRUE);
		tlsProperties.put("server.ssl.protocol",         "TLSv1.3");
		tlsProperties.put("server.ssl.enabledProtocols", "TLSv1.3,TLSv1.2");
		tlsProperties.put("server.ssl.bundle",           SslBundleNames.SERVER_TLS);
		tlsProperties.put("server.ssl.clientAuth",       ClientAuth.WANT.name());

		mutablePropertySources.addFirst(new OriginTrackedMapPropertySource("tomcat-tls", tlsProperties));
	}

    private static X509Certificate httpsServerRootCaCert(final KeyPair serverCaKeyPair) throws Exception {
		final SignUtil.ProviderAndAlgorithm signerPA = SignUtil.toProviderAndAlgorithm(serverCaKeyPair.getPrivate());
		return CertUtil.createSignedServerRootCaCert(signerPA.provider(), signerPA.algorithm(), serverCaKeyPair);
	}

    private static X509Certificate httpsClientRootCaCert(final KeyPair clientCaKeyPair) throws Exception {
		final SignUtil.ProviderAndAlgorithm signerPA = SignUtil.toProviderAndAlgorithm(clientCaKeyPair.getPrivate());
		return CertUtil.createSignedClientRootCaCert(signerPA.provider(), signerPA.algorithm(), clientCaKeyPair);
	}

	private static X509Certificate httpsServerCert(final PrivateKey caPrivateKey, final PublicKey serverPublicKey, final String serverAddress) throws Exception {
		final Set<String> sanDnsNames    = new LinkedHashSet<>(List.of("localhost"));
		final Set<String> sanIpAddresses = new LinkedHashSet<>(List.of("127.0.0.1", "::1"));
		if (InternetDomainName.isValid(serverAddress)) {
			sanDnsNames.add(serverAddress);
		} else if (InetAddresses.isUriInetAddress(serverAddress)) {
		    if (serverAddress.startsWith("[") && serverAddress.endsWith("]")) {
				sanIpAddresses.add(serverAddress.substring(1, serverAddress.length() - 1));
		    } else {
				sanIpAddresses.add(serverAddress);
		    }
		} else {
			throw new RuntimeException("Address is not a valid hostname or IP address");
		}

		final SignUtil.ProviderAndAlgorithm providerAndAlgorithm = SignUtil.toProviderAndAlgorithm(caPrivateKey);
		return CertUtil.createSignedServerCert(providerAndAlgorithm.provider(), providerAndAlgorithm.algorithm(), caPrivateKey, serverPublicKey, sanDnsNames, sanIpAddresses);
	}

	private static X509Certificate httpsClientCert(final PrivateKey caPrivateKey, final PublicKey clientPublicKey, final String emailAddress) throws Exception {
		final Set<String> sanEmailAddresses = new LinkedHashSet<>(List.of(emailAddress));
		final SignUtil.ProviderAndAlgorithm providerAndAlgorithm = SignUtil.toProviderAndAlgorithm(caPrivateKey);
		return CertUtil.createSignedClientCert(providerAndAlgorithm.provider(), providerAndAlgorithm.algorithm(), caPrivateKey, clientPublicKey, sanEmailAddresses);
	}

    private record SslAutoConfigProperties(Boolean enabled, String algorithm, String serverAddress, String clientEmail) {
        private static SslAutoConfigProperties find(final Collection<PropertySource<?>> propertySources) {
    		final Map<String, Object> foundPropertyValues = new HashMap<>();
    		for (final PropertySource<?> propertySource : propertySources) {
    			for (final String sslAutoConfigPropertyKey : SslAutoConfigPropertyNames.NAMES) {
    				if (propertySource.containsProperty(sslAutoConfigPropertyKey)) {
    					final Object foundPropertyValue = propertySource.getProperty(sslAutoConfigPropertyKey);
    					 // if a property is found in multiple property sources, only use the first of each property
    					foundPropertyValues.putIfAbsent(sslAutoConfigPropertyKey, foundPropertyValue);
    				}
    			}
    		}
    		final Boolean enabled       = Boolean.valueOf((String) foundPropertyValues.getOrDefault("server.ssl.auto-config.enabled",   "false"));
    		final String  algorithm     =                 (String) foundPropertyValues.getOrDefault("server.ssl.auto-config.algorithm", "EC-P384");
    		final String  serverAddress =                 (String) foundPropertyValues.getOrDefault("server.address",                   "localhost");
    		final String  clientEmail   =                 (String) foundPropertyValues.getOrDefault("client.ssl.auto-config.email",     "client@example.com");
    		return new SslAutoConfigProperties(enabled, algorithm, serverAddress, clientEmail);
    	}
    }

    public static class SslAutoConfigPropertyNames {
		public static final String ENABLED        = "server.ssl.auto-config.enabled";
		public static final String ALGORITHM      = "server.ssl.auto-config.algorithm";
		public static final String SERVER_ADDRESS = "server.address";
		public static final String CLIENT_EMAIL   = "client.ssl.auto-config.email";
		public static final List<String> NAMES = List.of(ENABLED, ALGORITHM, SERVER_ADDRESS, CLIENT_EMAIL);
	}

    public static class SslBundleNames {
	    public static final String CLIENT_STLS = "myclient-stls";
	    public static final String CLIENT_MTLS = "myclient-mtls";
	    public static final String SERVER_TLS  = "myserver";
	}

}