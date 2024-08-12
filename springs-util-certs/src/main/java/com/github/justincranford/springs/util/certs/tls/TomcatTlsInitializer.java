package com.github.justincranford.springs.util.certs.tls;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.boot.env.OriginTrackedMapPropertySource;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.env.MutablePropertySources;
import org.springframework.core.env.PropertySource;

import com.google.common.collect.Lists;
import com.google.common.net.InetAddresses;
import com.google.common.net.InternetDomainName;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@SuppressWarnings({"nls"})
public class TomcatTlsInitializer implements ApplicationContextInitializer<ConfigurableApplicationContext> {
    private record WantedProperties(String serverAddress, boolean sslAutoConfigEnabled, String sslAutoConfigAlgorithm) {
    	private static final List<String> PROPERTY_NAMES = List.of("server.address", "server.ssl.auto-config.enabled", "server.ssl.auto-config.algorithm");
    }

    @Override
    public void initialize(final ConfigurableApplicationContext configurableApplicationContext) {
		try {
	        final MutablePropertySources mutablePropertySources = configurableApplicationContext.getEnvironment().getPropertySources();
	        final WantedProperties wantedProperties = findWantedProperties(Lists.newArrayList(mutablePropertySources.iterator()));
			if (!wantedProperties.sslAutoConfigEnabled()) {
				return;
			}

			// generate cert/privateKey pairs for CA and server
			final List<KeyPair> keyPairs = KeyGenUtil.generateKeyPairs(2, wantedProperties.sslAutoConfigAlgorithm());
	        final KeyPair caKeyPair = keyPairs.get(0);
	        final KeyPair serverKeyPair = keyPairs.get(1);

	        final SignUtil.ProviderAndAlgorithm pa = SignUtil.toProviderAndAlgorithm(caKeyPair.getPrivate());

	        // TODO Create CA cert concurrently to server cert
	        final X509Certificate rootCaCert = CertUtil.createSignedRootCaCert(pa.provider(), pa.algorithm(), caKeyPair);
			rootCaCert.verify(rootCaCert.getPublicKey());

			final Set<String> sanDnsNames    = new LinkedHashSet<>(List.of("localhost"));
	        final Set<String> sanIpAddresses = new LinkedHashSet<>(List.of("127.0.0.1", "::1"));
			if (InternetDomainName.isValid(wantedProperties.serverAddress())) {
				sanDnsNames.add(wantedProperties.serverAddress());
			} else if (InetAddresses.isUriInetAddress(wantedProperties.serverAddress())) {
				sanIpAddresses.add(wantedProperties.serverAddress());
			}

	        final X509Certificate serverCert = CertUtil.createSignedServerCert(pa.provider(), pa.algorithm(), caKeyPair.getPrivate(), serverKeyPair.getPublic(), sanDnsNames, sanIpAddresses);
			serverCert.verify(caKeyPair.getPublic());

			final String rootCaCertPem       = PemUtil.toPem(rootCaCert);
			final String serverCertPem       = PemUtil.toPem(serverCert);
			final String serverPrivateKeyPem = PemUtil.toPem(serverKeyPair.getPrivate());

	        // Log server privateKey, server cert, and root CA cert as PEM
			log.info("CA certificate chain:\n{}\n",     rootCaCertPem);
			log.info("Server certificate chain:\n{}\n", serverCertPem);
	        log.info("Server private key:\n{}\n",       serverPrivateKeyPem);

	        // inject cert/privateKey pairs as properties in a map
	        final Map<String, Object> tlsProperties = new LinkedHashMap<>();
	        tlsProperties.put("spring.ssl.bundle.pem.client.truststore.certificate", rootCaCertPem);
	        tlsProperties.put("spring.ssl.bundle.pem.server.keystore.certificate", serverCertPem);
	        tlsProperties.put("spring.ssl.bundle.pem.server.keystore.privateKey", serverPrivateKeyPem);
	        tlsProperties.put("server.ssl.enabled", Boolean.TRUE);
	        tlsProperties.put("server.ssl.bundle", "server");
	        tlsProperties.put("server.ssl.protocol", "TLSv1.3");
	        tlsProperties.put("server.ssl.enabledProtocols", "TLSv1.3,TLSv1.2");

	        mutablePropertySources.addFirst(new OriginTrackedMapPropertySource("tomcat-tls", tlsProperties));
		} catch(Exception e) {
			throw new RuntimeException(e);
		}
    }

    private static WantedProperties findWantedProperties(final Collection<PropertySource<?>> propertySources) {
		final Map<String, Object> foundPropertyValues = new HashMap<>();
		for (final PropertySource<?> propertySource : propertySources) {
			for (final String wantedPropertyKey : WantedProperties.PROPERTY_NAMES) {
				if (propertySource.containsProperty(wantedPropertyKey)) {
					final Object foundPropertyValue = propertySource.getProperty(wantedPropertyKey);
					foundPropertyValues.putIfAbsent(wantedPropertyKey, foundPropertyValue);
				}
			}
		}
		final String  serverAddress          =                      (String) foundPropertyValues.getOrDefault("server.address",                   "localhost");
		final boolean sslAutoConfigEnabled   = Boolean.parseBoolean((String) foundPropertyValues.getOrDefault("server.ssl.auto-config.enabled",   "false"));
		final String  sslAutoConfigAlgorithm =                      (String) foundPropertyValues.getOrDefault("server.ssl.auto-config.algorithm", "EC-P384");
		return new WantedProperties(serverAddress, sslAutoConfigEnabled, sslAutoConfigAlgorithm);
	}
}