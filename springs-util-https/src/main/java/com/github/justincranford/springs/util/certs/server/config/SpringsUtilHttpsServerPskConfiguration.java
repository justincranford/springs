package com.github.justincranford.springs.util.certs.server.config;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.boot.web.embedded.jetty.JettyServerCustomizer;
import org.springframework.boot.web.embedded.jetty.JettyServletWebServerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.github.justincranford.springs.util.certs.server.TlsInitializer;
import com.github.justincranford.springs.util.certs.util.TlsPskUtil;

@SuppressWarnings({"static-method", "resource"})
@Configuration
public class SpringsUtilHttpsServerPskConfiguration {
    @Bean
    public JettyServletWebServerFactory jettyServletWebServerFactory(final SslBundles sslBundles) {
		final JettyServletWebServerFactory factory = new JettyServletWebServerFactory();
        factory.addServerCustomizers(new JettyServerCustomizer() {
			@Override
            public void customize(Server server) {
				final SslBundle                serverTlsPskBundle = sslBundles.getBundle(TlsInitializer.SslBundleNames.SERVER_TLS_PSK);
				final SslContextFactory.Server sslContextFactory  = TlsPskUtil.createServerSslContextFactory(serverTlsPskBundle);

				final ServerConnector serverConnector = new ServerConnector(server, sslContextFactory);
                serverConnector.setPort(9443);
                server.addConnector(serverConnector);
            }
        });
        return factory;
    }

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

//	@RequiredArgsConstructor
//	@Getter
//	public static class PSKKeyManager implements KeyManager {
//	    private final byte[] identity;
//	    private final byte[] psk;
//	}
}
