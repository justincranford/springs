package com.github.justincranford.springs.server.authentication.filterchain;

import com.github.justincranford.springs.server.authentication.AbstractIT;
import com.github.justincranford.springs.util.http.client.util.RestTemplateUtil;
import org.assertj.core.api.AbstractThrowableAssert;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.web.client.HttpClientErrorException;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class SpringsServerAuthenticationSecurityFilterChainConfigurationIT extends AbstractIT {
	private static final String NO_AUTHORIZE = null;

	@Test
    void testRoot_notAuthenticated() {
		RestTemplateUtil.anyGet(stlsRestTemplate(), httpsBaseUrl() + "/", NO_AUTHORIZE, String.class);
	}

    @Test
    void testIndexHtml_notAuthenticated() {
		RestTemplateUtil.anyGet(stlsRestTemplate(), httpsBaseUrl() + "/login.html", NO_AUTHORIZE, String.class);
	}

    @Test
    void testHomeHtml_notAuthenticated() {
		RestTemplateUtil.anyGet(stlsRestTemplate(), httpsBaseUrl() + "/home.html", NO_AUTHORIZE, String.class);
	}

    @Test
    void testLogin_notAuthenticated() {
		RestTemplateUtil.anyGet(stlsRestTemplate(), httpsBaseUrl() + "/login", NO_AUTHORIZE, String.class);
	}

    @Test
    void testLogout_notAuthenticated() {
		RestTemplateUtil.anyGet(stlsRestTemplate(), httpsBaseUrl() + "/logout", NO_AUTHORIZE, String.class);
	}

    @Test
    void testHelloWorld_notAuthenticated() {
		RestTemplateUtil.anyGet(stlsRestTemplate(), httpsBaseUrl() + "/helloworld", NO_AUTHORIZE, String.class);
	}

    @Test
    void testNotFound_notAuthenticated() {
		verifyNotFound(httpsBaseUrl() + "/notfound");
	}

    @Test
    void testSecureNotFound_notAuthenticated() {
		RestTemplateUtil.anyGet(stlsRestTemplate(), httpsBaseUrl() + "/secure/notfound", NO_AUTHORIZE, String.class);
    }

    @Disabled
    @Test
    void testSecureNotFound_authenticated() {
		RestTemplateUtil.anyGet(stlsRestTemplate(), httpsBaseUrl() + "/secure/notfound", NO_AUTHORIZE, String.class);
    }

	private void verifyNotFound(final String url) {
		final AbstractThrowableAssert<?, ? extends Throwable> assertThatThrownBy = assertThatThrownBy(
			() -> RestTemplateUtil.anyGet(stlsRestTemplate(), url, NO_AUTHORIZE, String.class)
		);
		assertThatThrownBy
			.isInstanceOf(RuntimeException.class)
			.hasMessage("HTTP Error Response: [404 NOT_FOUND]")
			.cause()
			.isInstanceOf(HttpClientErrorException.NotFound.class);
	}
}
