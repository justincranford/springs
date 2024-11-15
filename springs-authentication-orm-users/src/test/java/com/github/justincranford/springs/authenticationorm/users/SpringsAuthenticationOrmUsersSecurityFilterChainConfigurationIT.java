package com.github.justincranford.springs.authenticationorm.users;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.assertj.core.api.AbstractThrowableAssert;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.web.client.HttpClientErrorException;

import com.github.justincranford.springs.util.http.client.util.RestTemplateUtil;

public class SpringsAuthenticationOrmUsersSecurityFilterChainConfigurationIT extends AbstractIT {
    @Test
    void testRoot_notAuthenticated() throws Exception {
		RestTemplateUtil.anyGet(stlsRestTemplate(), httpsBaseUrl() + "/", String.class);
	}

    @Test
    void testIndexHtml_notAuthenticated() throws Exception {
		RestTemplateUtil.anyGet(stlsRestTemplate(), httpsBaseUrl() + "/index.html", String.class);
	}

    @Test
    void testHomeHtml_notAuthenticated() throws Exception {
		RestTemplateUtil.anyGet(stlsRestTemplate(), httpsBaseUrl() + "/home.html", String.class);
	}

    @Test
    void testLogin_notAuthenticated() throws Exception {
		RestTemplateUtil.anyGet(stlsRestTemplate(), httpsBaseUrl() + "/login", String.class);
	}

    @Test
    void testLogout_notAuthenticated() throws Exception {
		RestTemplateUtil.anyGet(stlsRestTemplate(), httpsBaseUrl() + "/logout", String.class);
	}

    @Test
    void testHelloWorld_notAuthenticated() throws Exception {
		RestTemplateUtil.anyGet(stlsRestTemplate(), httpsBaseUrl() + "/helloworld", String.class);
	}

    @Test
    void testNotFound_notAuthenticated() throws Exception {
		verifyNotFound(httpsBaseUrl() + "/notfound");
	}

    @Test
    void testSecureNotFound_notAuthenticated() throws Exception {
		RestTemplateUtil.anyGet(stlsRestTemplate(), httpsBaseUrl() + "/secure/notfound", String.class);
    }

    @Disabled
    @Test
    void testSecureNotFound_authenticated() throws Exception {
		RestTemplateUtil.anyGet(stlsRestTemplate(), httpsBaseUrl() + "/secure/notfound", String.class);
    }

	private void verifyNotFound(final String url) {
		final AbstractThrowableAssert<?, ? extends Throwable> assertThatThrownBy = assertThatThrownBy(
			() -> RestTemplateUtil.anyGet(stlsRestTemplate(), url, String.class)
		);
		assertThatThrownBy
			.isInstanceOf(RuntimeException.class)
			.hasMessage("HTTP Error Response: [404 NOT_FOUND]")
			.cause()
			.isInstanceOf(HttpClientErrorException.NotFound.class);
	}
}