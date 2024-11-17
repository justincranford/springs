package com.github.justincranford.springs.persistenceorm.sessions;

import com.github.justincranford.springs.util.http.client.util.RestTemplateUtil;
import com.github.justincranford.springs.util.http.server.helloworld.HelloWorldController;
import lombok.extern.slf4j.Slf4j;
import org.apache.hc.core5.http.NoHttpResponseException;
import org.assertj.core.api.AbstractThrowableAssert;
import org.assertj.core.api.Fail;
import org.junit.jupiter.api.Test;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@Slf4j
public class HttpsHelloWorldIT extends AbstractIT {
    private static final String AUTHORIZE = null;

    @Test
    void testHttpFailure() {
        final AbstractThrowableAssert<?,? extends Throwable> assertThatThrownBy = assertThatThrownBy(
            () -> RestTemplateUtil.plainGet(httpRestTemplate(), httpBaseUrl() + HelloWorldController.Constants.PATH, AUTHORIZE, String.class)
        );
        final String webServerClassName = webServerApplicationContext().getWebServer().getClass().getName();
        if (webServerClassName.contains("Tomcat")) {
            assertThatThrownBy
                .isInstanceOf(RuntimeException.class)
                .hasMessage("HTTP Error Response: [400 BAD_REQUEST]")
                .cause()
                .isInstanceOf(HttpClientErrorException.class)
                .hasMessage("400 : \"Bad Request<EOL><EOL>This combination of host and port requires TLS.<EOL><EOL>\"");
        } else if (webServerClassName.contains("Jetty")) {
            assertThatThrownBy
                .isInstanceOf(RuntimeException.class)
                .hasMessage("I/O error on GET request for \"http://localhost:8443/helloworld\": localhost:8443 failed to respond")
                .cause()
                .isInstanceOf(NoHttpResponseException.class)
                .hasMessage("localhost:8443 failed to respond");
        } else {
            Fail.fail("Unsupported webserver class: {}", webServerClassName);
        }
    }

    @Test
    void testHttpsSuccessServerTls() {
        httpsGetHelloWorldInterceptSessionId(stlsRestTemplate());
    }

    private void httpsGetHelloWorldInterceptSessionId(final RestTemplate restTemplate) {
        final SessionIdCookieInterceptor sessionIdCookieInterceptor = new SessionIdCookieInterceptor();
        restTemplate.getInterceptors().add(sessionIdCookieInterceptor);
        try {
            // CREATE SESSION

            final String helloWorld = RestTemplateUtil.plainGet(restTemplate, httpsBaseUrl() + HelloWorldController.Constants.PATH, AUTHORIZE, String.class);
            assertThat(helloWorld).isEqualTo(HelloWorldController.Constants.RESPONSE_BODY);

            final List<String> helloWorldSessionIdCookies = sessionIdCookieInterceptor.getSessionIdCookies();
            assertThat(helloWorldSessionIdCookies).isNotNull().hasSize(1);
            final String helloWorldSessionId = helloWorldSessionIdCookies.getFirst();
            assertThat(helloWorldSessionId).isNotBlank();
            log.info("Hello World Session ID: " + helloWorldSessionId);
            prettyJson().log(sessionOrmRepository().findAll());

            // DELETE SESSION

            final String logout = RestTemplateUtil.plainGet(restTemplate, httpsBaseUrl() + "/logout", AUTHORIZE, String.class);
            assertThat(logout).isEqualTo(HelloWorldController.Constants.RESPONSE_BODY);

            final List<String> logoutSessionIdCookies = sessionIdCookieInterceptor.getSessionIdCookies();
            assertThat(logoutSessionIdCookies).isNull();
        } finally {
            mtlsRestTemplate().getInterceptors().remove(sessionIdCookieInterceptor);
        }

    }

    @Test
    void testHttpsSuccessMutualTls() {
        httpsGetHelloWorldInterceptSessionId(mtlsRestTemplate());
    }
}
