package com.github.justincranford.springs.util.https.client.config;

import com.github.justincranford.springs.util.https.server.initializer.TlsEnabledByDefaultInitializer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.net.ssl.SSLContext;

@Configuration
@SuppressWarnings({"unused"})
public class SpringsUtilTlsClientsConfiguration {
    @Autowired
    private SslBundles sslBundles;

    @ConditionalOnProperty(name = TlsEnabledByDefaultInitializer.SslAutoConfigPropertyNames.ENABLED)
    @Qualifier("stlsSslContext")
    @Bean
    public SSLContext stlsSslContext() {
        final SslBundle clientSslBundle = this.sslBundles.getBundle(TlsEnabledByDefaultInitializer.SslBundleNames.CLIENT_STLS_CERT);
        return clientSslBundle.createSslContext();
    }

    @ConditionalOnProperty(name = TlsEnabledByDefaultInitializer.SslAutoConfigPropertyNames.ENABLED)
    @Qualifier("mtlsSslContext")
    @Bean
    public SSLContext mtlsSslContext() {
        final SslBundle clientSslBundle = this.sslBundles.getBundle(TlsEnabledByDefaultInitializer.SslBundleNames.CLIENT_MTLS_CERT);
        return clientSslBundle.createSslContext();
    }

    @ConditionalOnProperty(name = TlsEnabledByDefaultInitializer.SslAutoConfigPropertyNames.ENABLED)
    @Qualifier("ptlsSslContext")
    @Bean
    public SSLContext ptlsSslContext() {
        final SslBundle clientSslBundle = this.sslBundles.getBundle(TlsEnabledByDefaultInitializer.SslBundleNames.CLIENT_TLS_PSK);
        return clientSslBundle.createSslContext();
    }
}
