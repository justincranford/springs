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
import java.util.concurrent.Future;

import org.springframework.boot.env.OriginTrackedMapPropertySource;
import org.springframework.boot.web.server.Ssl.ClientAuth;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.env.MutablePropertySources;
import org.springframework.core.env.PropertySource;

import com.github.justincranford.springs.util.basic.ThreadUtil;
import com.google.common.collect.Lists;
import com.google.common.net.InetAddresses;
import com.google.common.net.InternetDomainName;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@SuppressWarnings({"nls"})
public class TomcatTlsInitializer implements ApplicationContextInitializer<ConfigurableApplicationContext> {
    public static final String CLIENT_BUNDLE_SERVER_AUTHENTICATION = "myclient-server-authentication";
    public static final String CLIENT_BUNDLE_MUTUAL_AUTHENTICATION = "myclient-mutual-authentication";
    public static final String SERVER_BUNDLE = "myserver";

    private record WantedProperties(String serverAddress, boolean sslAutoConfigEnabled, String sslAutoConfigAlgorithm, String clientEmail) {
    	private static final List<String> PROPERTY_NAMES = List.of(
			"server.address",
			"server.ssl.auto-config.enabled",
			"server.ssl.auto-config.algorithm",
			"client.ssl.email"
		);
    }

    @Override
    public void initialize(final ConfigurableApplicationContext configurableApplicationContext) {
		try {
	        final MutablePropertySources mutablePropertySources = configurableApplicationContext.getEnvironment().getPropertySources();
	        final WantedProperties wantedProperties = findWantedProperties(Lists.newArrayList(mutablePropertySources.iterator()));
			if (!wantedProperties.sslAutoConfigEnabled()) {
				return;
			}

			final List<KeyPair> keyPairs = new LinkedList<>(KeyGenUtil.generateKeyPairs(4, wantedProperties.sslAutoConfigAlgorithm()));
	        final KeyPair httpsServerRootCaKeyPair = keyPairs.removeFirst();
	        final KeyPair httpsServerKeyPair       = keyPairs.removeFirst();
	        final KeyPair httpsClientRootCaKeyPair = keyPairs.removeFirst();
	        final KeyPair httpsClientKeyPair       = keyPairs.removeFirst();

			final Future<X509Certificate> futureHttpsServerRootCaCert = ThreadUtil.async(() -> httpsServerRootCaCert(httpsServerRootCaKeyPair));
			final Future<X509Certificate> futureHttpsServerCert       = ThreadUtil.async(() -> httpsServerCert(httpsServerRootCaKeyPair.getPrivate(), httpsServerKeyPair.getPublic(), wantedProperties.serverAddress()));
			final Future<X509Certificate> futureHttpsClientRootCaCert = ThreadUtil.async(() -> httpsClientRootCaCert(httpsClientRootCaKeyPair));
			final Future<X509Certificate> futureHttpsClientCert       = ThreadUtil.async(() -> httpsClientCert(httpsClientRootCaKeyPair.getPrivate(), httpsClientKeyPair.getPublic(), wantedProperties.clientEmail()));

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

			log.info("HTTPS Server Root CA:\n{}{}", httpsServerRootCaCertPem, httpsServerRootCaPrivateKeyPem);
			log.info("HTTPS Server:\n{}{}",         httpsServerCertPem,       httpsServerPrivateKeyPem);
			log.info("HTTPS Client Root CA:\n{}{}", httpsClientRootCaCertPem, httpsClientRootCaPrivateKeyPem);
			log.info("HTTPS Client:\n{}{}",         httpsClientCertPem,       httpsClientPrivateKeyPem);

	        // inject cert/privateKey pairs as properties in a map
	        final Map<String, Object> tlsProperties = new LinkedHashMap<>();
	        tlsProperties.put("spring.ssl.bundle.pem." + CLIENT_BUNDLE_SERVER_AUTHENTICATION + ".truststore.certificate", httpsServerRootCaCertPem);

	        tlsProperties.put("spring.ssl.bundle.pem." + CLIENT_BUNDLE_MUTUAL_AUTHENTICATION + ".keystore.certificate",   httpsClientCertPem);
	        tlsProperties.put("spring.ssl.bundle.pem." + CLIENT_BUNDLE_MUTUAL_AUTHENTICATION + ".keystore.privateKey",    httpsClientPrivateKeyPem);
	        tlsProperties.put("spring.ssl.bundle.pem." + CLIENT_BUNDLE_MUTUAL_AUTHENTICATION + ".truststore.certificate", httpsServerRootCaCertPem);

	        tlsProperties.put("spring.ssl.bundle.pem." + SERVER_BUNDLE + ".keystore.certificate",   httpsServerCertPem);
	        tlsProperties.put("spring.ssl.bundle.pem." + SERVER_BUNDLE + ".keystore.privateKey",    httpsServerPrivateKeyPem);
			tlsProperties.put("spring.ssl.bundle.pem." + SERVER_BUNDLE + ".truststore.certificate", httpsClientRootCaCertPem);

			tlsProperties.put("server.ssl.enabled",          Boolean.TRUE);
	        tlsProperties.put("server.ssl.protocol",         "TLSv1.3");
	        tlsProperties.put("server.ssl.enabledProtocols", "TLSv1.3,TLSv1.2");
	        tlsProperties.put("server.ssl.bundle",           SERVER_BUNDLE);
	        tlsProperties.put("server.ssl.clientAuth",       ClientAuth.WANT.name());

	        mutablePropertySources.addFirst(new OriginTrackedMapPropertySource("tomcat-tls", tlsProperties));
		} catch(Exception e) {
			throw new RuntimeException(e);
		}
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
		final String  clientEmail            =                      (String) foundPropertyValues.getOrDefault("client.ssl.email",                 "client@example.com");
		return new WantedProperties(serverAddress, sslAutoConfigEnabled, sslAutoConfigAlgorithm, clientEmail);
	}
}