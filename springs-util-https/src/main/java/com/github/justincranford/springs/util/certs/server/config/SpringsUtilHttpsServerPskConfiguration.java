package com.github.justincranford.springs.util.certs.server.config;

//import java.security.KeyStore;
//
//import javax.crypto.SecretKey;
//import javax.net.ssl.KeyManager;
//import javax.net.ssl.SSLContext;
//
////import org.apache.catalina.Context;
////import org.apache.catalina.connector.Connector;
////import org.apache.tomcat.util.net.SSLHostConfig;
//import org.bouncycastle.tls.BasicTlsPSKIdentity;
//import org.bouncycastle.tls.TlsPSKIdentity;
//import org.springframework.boot.ssl.SslBundle;
//import org.springframework.boot.ssl.SslBundleKey;
//import org.springframework.boot.ssl.SslBundles;
//import org.springframework.boot.ssl.SslStoreBundle;
//import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
//import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
//import org.springframework.util.Assert;
//
//import com.github.justincranford.springs.util.basic.SecureRandomUtil;
//import com.github.justincranford.springs.util.certs.server.TlsInitializer;
//
//import lombok.Getter;
//import lombok.RequiredArgsConstructor;

@Configuration
@SuppressWarnings({"nls", "static-method"})
public class SpringsUtilHttpsServerPskConfiguration {
//    @Bean
//    public TomcatServletWebServerFactory servletContainer2(final SslBundles sslBundles) {
//        final TomcatServletWebServerFactory factory = new TomcatServletWebServerFactory();
//
//        final SslBundle clientSslBundle = sslBundles.getBundle(TlsInitializer.SslBundleNames.CLIENT_MTLS_CERT);
//        final SSLContext sslContext = createPskSslContext(clientSslBundle);
//
//        Connector pskConnector = new Connector(TomcatServletWebServerFactory.DEFAULT_PROTOCOL);
//        pskConnector.setScheme("https");
//        pskConnector.setSecure(true);
//        pskConnector.setPort(8444);
////        pskConnector.setAttribute("sslContext", sslContext);
//
//        SSLHostConfig sslHostConfig = new SSLHostConfig();
////        sslHostConfig.setSslContext(sslContext);
//
//        pskConnector.addSslHostConfig(sslHostConfig);
//        factory.addAdditionalTomcatConnectors(pskConnector);
//
//        return factory;
//    }
//    @Bean
//    public TomcatServletWebServerFactory servletContainer(final SslBundles sslBundles) {
//    	return new TomcatServletWebServerFactory() {
//        	@Override
//            protected void postProcessContext(Context context) {
//                final SslBundle clientSslBundle = sslBundles.getBundle(TlsInitializer.SslBundleNames.CLIENT_MTLS_CERT);
//                final SSLContext sslContext = createPskSslContext(clientSslBundle);
//
//                Connector pskConnector = new Connector(TomcatServletWebServerFactory.DEFAULT_PROTOCOL);
//                pskConnector.setScheme("https");
//                pskConnector.setSecure(true);
//                pskConnector.setPort(8444); // Use a different port for PSK
////				pskConnector.setSslContext(sslContext);
//                this.addAdditionalTomcatConnectors(pskConnector);
//            }
//        };
//    }
//    public static SSLContext createPskSslContext(final SslBundle sslBundle) {
//		try {
//	        final SslStoreBundle sslStoreBundle  = sslBundle.getStores();
//	        final KeyStore       keyStore        = sslStoreBundle.getKeyStore();
//	        Assert.isNull(sslStoreBundle.getTrustStore(), "TLS PSK TrustStore expected to be null");
//	        final SslBundleKey sslBundleKey = sslBundle.getKey();
//			final String keyAlias    = sslBundleKey.getAlias();
//			final char[] keyPassword = sslBundleKey.getPassword().toCharArray();
//	        final SecretKey secretKey = (SecretKey) keyStore.getKey(keyAlias, keyPassword);
//	        final TlsPSKIdentity pskIdentityManager = new BasicTlsPSKIdentity(keyAlias.getBytes(), secretKey.getEncoded());
//			final PSKKeyManager pskKeyManager = new PSKKeyManager(pskIdentityManager.getPSKIdentity(), pskIdentityManager.getPSK());
//			final SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
//			sslContext.init(new KeyManager[] {pskKeyManager}, null, SecureRandomUtil.SECURE_RANDOM);
//			return sslContext;
//		} catch (Exception e) {
//			throw new RuntimeException(e);
//		}
//	}
//
//	@RequiredArgsConstructor
//	@Getter
//	public static class PSKKeyManager implements KeyManager {
//	    private final byte[] identity;
//	    private final byte[] psk;
//	}
}
