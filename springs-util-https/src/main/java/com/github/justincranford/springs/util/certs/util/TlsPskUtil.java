package com.github.justincranford.springs.util.certs.util;

import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.crypto.SecretKey;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509TrustManager;

import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundleKey;
import org.springframework.boot.ssl.SslStoreBundle;
import org.springframework.util.Assert;

import com.github.justincranford.springs.util.basic.SecureRandomUtil;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@SuppressWarnings("nls")
public class TlsPskUtil {
	public static final String PSK_TLS_PROTOCOL = "TLSv1.2";
	public static final String[] PSK_TLS_PROTOCOLS = new String[] {PSK_TLS_PROTOCOL};
	public static final String[] PSK_SUPPORTED_CIPHER_SUITES = new String[] {
	    "TLS_CHACHA20_POLY1305_SHA256", // TLS 1.3, {0x13, 0x03}
	    "TLS_AES_256_GCM_SHA384",       // TLS 1.3, {0x13, 0x02}
	    "TLS_AES_128_GCM_SHA256",       // TLS 1.3, {0x13, 0x01}
	    "TLS_PSK_WITH_AES_128_CBC_SHA256",
	    "TLS_PSK_WITH_NULL_SHA256",
//	    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", // TLS 1.2, {0xcc, 0xa9}
//	    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",       // TLS 1.2, {0xc0, 0x2c}
//	    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",       // TLS 1.2, {0xc0, 0x2b}
//	    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",   // TLS 1.2, {0xcc, 0xa8}
//	    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",         // TLS 1.2, {0xc0, 0x30}
//	    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",         // TLS 1.2, {0xc0, 0x2f}
//	    "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",     // TLS 1.2, {0xcc, 0xaa}
//	    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",           // TLS 1.2, {0x00, 0x9f}
//	    "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",           // TLS 1.2, {0x00, 0xa3}
//	    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",           // TLS 1.2, {0x00, 0x9e}
//	    "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",           // TLS 1.2, {0x00, 0xa2}
//	    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",       // TLS 1.2, {0xc0, 0x24}
//	    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",         // TLS 1.2, {0xc0, 0x28}
//	    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",       // TLS 1.2, {0xc0, 0x23}
//	    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",         // TLS 1.2, {0xc0, 0x27}
//	    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",           // TLS 1.2, {0x00, 0x6b}
//	    "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",           // TLS 1.2, {0x00, 0x6a}
//	    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",           // TLS 1.2, {0x00, 0x67}
//	    "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",           // TLS 1.2, {0x00, 0x40}
//	    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",          // TLS 1.0, {0xc0, 0x0a}
//	    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",            // TLS 1.0, {0xc0, 0x14}
//	    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",          // TLS 1.0, {0xc0, 0x09}
//	    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",            // TLS 1.0, {0xc0, 0x13}
//	    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",              // TLS 1.0, {0x00, 0x39}
//	    "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",              // TLS 1.0, {0x00, 0x38}
//	    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",              // TLS 1.0, {0x00, 0x33}
//	    "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",              // TLS 1.0, {0x00, 0x32}
//	    "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",              // TLS 1.0, {0x00, 0xff}
	};

	public static SslContextFactory.Client createClientSslContextFactory(final SslBundle sslBundle) {
        final SSLContext sslContext = createPskSslContext(sslBundle);
        final SslContextFactory.Client sslContextFactory = new SslContextFactory.Client();
        sslContextFactory.setSslContext(sslContext);
        sslContextFactory.setIncludeProtocols(PSK_TLS_PROTOCOLS);
        sslContextFactory.setIncludeCipherSuites(PSK_SUPPORTED_CIPHER_SUITES);
        return sslContextFactory;
    }

    public static SslContextFactory.Server createServerSslContextFactory(final SslBundle sslBundle) {
        final SSLContext sslContext = createPskSslContext(sslBundle);
    	final SslContextFactory.Server sslContextFactory = new SslContextFactory.Server();
        sslContextFactory.setSslContext(sslContext);
        sslContextFactory.setIncludeProtocols(PSK_TLS_PROTOCOLS);
        sslContextFactory.setIncludeCipherSuites(PSK_SUPPORTED_CIPHER_SUITES);
        return sslContextFactory;
    }

    public static SSLContext createPskSslContext(final SslBundle sslBundle) {
		try {
			final KeyManager[]   keyManagers   = new KeyManager[]   { createPskKeyManager(sslBundle) };
			final TrustManager[] trustManagers = new TrustManager[] { new PskTrustManager() };
			final SSLContext     sslContext    = SSLContext.getInstance(PSK_TLS_PROTOCOL, "BCJSSE");
			sslContext.init(keyManagers, trustManagers, SecureRandomUtil.SECURE_RANDOM);
			return sslContext;
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	private static PskKeyManager createPskKeyManager(final SslBundle sslBundle) {
		try {
			final SslStoreBundle sslStoreBundle  = sslBundle.getStores();
			final KeyStore       keyStore        = sslStoreBundle.getKeyStore();
			Assert.isNull(sslStoreBundle.getTrustStore(), "TLS PSK TrustStore expected to be null");
			final SslBundleKey sslBundleKey = sslBundle.getKey();
			final String keyAlias    = sslBundleKey.getAlias();
			final char[] keyPassword = sslBundleKey.getPassword().toCharArray();
			final SecretKey secretKey = (SecretKey) keyStore.getKey(keyAlias, keyPassword);
//			final TlsPSKIdentity pskIdentityManager = new BasicTlsPSKIdentity(keyAlias.getBytes(), secretKey.getEncoded());
			return new PskKeyManager(keyAlias, secretKey.getEncoded());
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	@RequiredArgsConstructor
	@Getter
	public static class PskKeyManager extends X509ExtendedKeyManager {
	    private final String identity;
	    private final byte[] psk;

	    @Override
	    public String chooseClientAlias(String[] keyType, Principal[] issuers, java.net.Socket socket) {
	        return this.identity;  // Choose the PSK identity for the client
	    }
		@Override
		public String[] getClientAliases(String keyType, Principal[] issuers) {
			return new String[] {this.identity};
		}

	    @Override
	    public String chooseServerAlias(String keyType, Principal[] issuers, java.net.Socket socket) {
	        return this.identity;  // Choose the PSK identity for the server
	    }
		@Override
		public String[] getServerAliases(String keyType, Principal[] issuers) {
			return new String[] {this.identity};
		}

	    @Override
	    public X509Certificate[] getCertificateChain(String alias) {
	        return null; // PSK doesn't use certificates
	    }

	    @Override
	    public PrivateKey getPrivateKey(String alias) {
	        return null; // PSK doesn't use private keys
	    }
    }

	public static class PskTrustManager implements X509TrustManager {
	    @Override
	    public void checkClientTrusted(X509Certificate[] chain, String authType) {
	        // No-op: We don't check client certificates in PSK mode
	        // In PSK, there's no need to verify client certificates.
	    	throw new UnsupportedOperationException();
	    }
	    @Override
	    public void checkServerTrusted(X509Certificate[] chain, String authType) {
	        // No-op: We don't check server certificates in PSK mode
	        // In PSK, there's no need to verify server certificates.
	    	throw new UnsupportedOperationException();
	    }
	    @Override
	    public X509Certificate[] getAcceptedIssuers() {
	        return new X509Certificate[0]; // No accepted issuers in PSK
	    }
	}
}
