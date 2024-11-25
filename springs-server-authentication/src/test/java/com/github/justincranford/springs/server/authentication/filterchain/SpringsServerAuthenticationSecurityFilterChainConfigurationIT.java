package com.github.justincranford.springs.server.authentication.filterchain;

import com.github.justincranford.springs.server.authentication.AbstractIT;
import com.github.justincranford.springs.util.http.client.util.RestTemplateUtil;
import org.assertj.core.api.AbstractThrowableAssert;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.web.client.HttpClientErrorException;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class SpringsServerAuthenticationSecurityFilterChainConfigurationIT extends AbstractIT {
	private static final String AUTHORIZE = null;

	@Test
    void testRoot_notAuthenticated() {
		RestTemplateUtil.anyGet(stlsRestTemplate(), httpsBaseUrl() + "/", AUTHORIZE, String.class);
	}

    @Test
    void testIndexHtml_notAuthenticated() {
		RestTemplateUtil.anyGet(stlsRestTemplate(), httpsBaseUrl() + "/index.html", AUTHORIZE, String.class);
	}

    @Test
    void testHomeHtml_notAuthenticated() {
		RestTemplateUtil.anyGet(stlsRestTemplate(), httpsBaseUrl() + "/home.html", AUTHORIZE, String.class);
	}

    @Test
    void testLogin_notAuthenticated() {
		RestTemplateUtil.anyGet(stlsRestTemplate(), httpsBaseUrl() + "/login", AUTHORIZE, String.class);
	}

    @Test
    void testLogout_notAuthenticated() {
		RestTemplateUtil.anyGet(stlsRestTemplate(), httpsBaseUrl() + "/logout", AUTHORIZE, String.class);
	}

    @Test
    void testHelloWorld_notAuthenticated() {
		RestTemplateUtil.anyGet(stlsRestTemplate(), httpsBaseUrl() + "/helloworld", AUTHORIZE, String.class);
	}

    @Test
    void testNotFound_notAuthenticated() {
		verifyNotFound(httpsBaseUrl() + "/notfound");
	}

    @Test
    void testSecureNotFound_notAuthenticated() {
		RestTemplateUtil.anyGet(stlsRestTemplate(), httpsBaseUrl() + "/secure/notfound", AUTHORIZE, String.class);
    }

    @Disabled
    @Test
    void testSecureNotFound_authenticated() {
		RestTemplateUtil.anyGet(stlsRestTemplate(), httpsBaseUrl() + "/secure/notfound", AUTHORIZE, String.class);
    }

	private void verifyNotFound(final String url) {
		final AbstractThrowableAssert<?, ? extends Throwable> assertThatThrownBy = assertThatThrownBy(
			() -> RestTemplateUtil.anyGet(stlsRestTemplate(), url, AUTHORIZE, String.class)
		);
		assertThatThrownBy
			.isInstanceOf(RuntimeException.class)
			.hasMessage("HTTP Error Response: [404 NOT_FOUND]")
			.cause()
			.isInstanceOf(HttpClientErrorException.NotFound.class);
	}
}
