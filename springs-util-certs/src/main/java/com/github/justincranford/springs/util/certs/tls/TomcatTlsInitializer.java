package com.github.justincranford.springs.util.certs.tls;

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

			final List<KeyPair> keyPairs = new LinkedList<>(KeyGenUtil.generateKeyPairs(2, wantedProperties.sslAutoConfigAlgorithm()));
	        final KeyPair rootCaKeyPair      = keyPairs.removeFirst();
	        final KeyPair httpsServerKeyPair = keyPairs.removeFirst();

	        final X509Certificate rootCaCert      = rootCaCert(rootCaKeyPair);
			final X509Certificate httpsServerCert = httpsServerCert(rootCaKeyPair.getPrivate(), httpsServerKeyPair.getPublic(), wantedProperties.serverAddress());

			rootCaCert.verify(rootCaKeyPair.getPublic());
			httpsServerCert.verify(rootCaKeyPair.getPublic());

			final String rootCaCertPem            = PemUtil.toPem(rootCaCert);
			final String rootCaPrivateKeyPem      = PemUtil.toPem(rootCaKeyPair.getPrivate());
			final String httpsServerCertPem       = PemUtil.toPem(httpsServerCert);
			final String httpsServerPrivateKeyPem = PemUtil.toPem(httpsServerKeyPair.getPrivate());

	        // Log server privateKey, server cert, and root CA cert as PEM
			log.info("Root CA certificate:\n{}",    rootCaCertPem);
	        log.info("Root CA private key:\n{}",    rootCaPrivateKeyPem);
			log.info("TLS server certificate:\n{}", httpsServerCertPem);
	        log.info("TLS server private key:\n{}", httpsServerPrivateKeyPem);

	        // inject cert/privateKey pairs as properties in a map
	        final Map<String, Object> tlsProperties = new LinkedHashMap<>();
	        tlsProperties.put("spring.ssl.bundle.pem.client.truststore.certificate", rootCaCertPem);
	        tlsProperties.put("spring.ssl.bundle.pem.server.keystore.certificate", httpsServerCertPem);
	        tlsProperties.put("spring.ssl.bundle.pem.server.keystore.privateKey", httpsServerPrivateKeyPem);
	        tlsProperties.put("server.ssl.enabled", Boolean.TRUE);
	        tlsProperties.put("server.ssl.bundle", "server");
	        tlsProperties.put("server.ssl.protocol", "TLSv1.3");
	        tlsProperties.put("server.ssl.enabledProtocols", "TLSv1.3,TLSv1.2");

	        mutablePropertySources.addFirst(new OriginTrackedMapPropertySource("tomcat-tls", tlsProperties));
		} catch(Exception e) {
			throw new RuntimeException(e);
		}
    }

	private static X509Certificate rootCaCert(final KeyPair caKeyPair) throws Exception {
		final SignUtil.ProviderAndAlgorithm signerPA = SignUtil.toProviderAndAlgorithm(caKeyPair.getPrivate());
		return CertUtil.createSignedRootCaCert(signerPA.provider(), signerPA.algorithm(), caKeyPair);
	}

	private static X509Certificate httpsServerCert(final PrivateKey caPrivateKey, final PublicKey serverPublicKey, final String serverAddress) throws Exception {
		final Set<String> sanDnsNames    = new LinkedHashSet<>(List.of("localhost"));
		final Set<String> sanIpAddresses = new LinkedHashSet<>(List.of("127.0.0.1", "::1"));
		if (InternetDomainName.isValid(serverAddress)) {
			sanDnsNames.add(serverAddress);
		} else if (InetAddresses.isUriInetAddress(serverAddress)) {
			sanIpAddresses.add(serverAddress);
		} else {
			throw new RuntimeException("Address is not a valid hostname or IP address");
		}

		final SignUtil.ProviderAndAlgorithm providerAndAlgorithm = SignUtil.toProviderAndAlgorithm(caPrivateKey);
		return CertUtil.createSignedServerCert(providerAndAlgorithm.provider(), providerAndAlgorithm.algorithm(), caPrivateKey, serverPublicKey, sanDnsNames, sanIpAddresses);
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