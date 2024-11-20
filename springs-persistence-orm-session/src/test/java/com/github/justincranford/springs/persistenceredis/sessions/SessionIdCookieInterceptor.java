package com.github.justincranford.springs.persistenceredis.sessions;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpRequest;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.util.StreamUtils;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

//	================================================================
//	Example Response Headers
//	================================================================
//	Date=[Fri, 15 Nov 2024 01:24:48 GMT]
//	Content-Type=[plain/text;charset=UTF-8]
//	X-Content-Type-Options=[nosniff]
//	X-XSS-Protection=[0]
//	Cache-Control=[no-cache, no-store, max-age=0, must-revalidate]
//	Pragma=[no-cache]
//	Expires=[0]
//	Strict-Transport-Security=[max-age=31536000 ; includeSubDomains]
//	X-Frame-Options=[DENY]
//	Content-Length=[11]
//	JSESSIONID=node0sh0uov655g6mrkeksueov3630.node0; Path=/; Secure
@Slf4j
public class SessionIdCookieInterceptor implements ClientHttpRequestInterceptor {
	@Getter
	private List<String> sessionIdCookies;

	@Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution) throws IOException {
        ClientHttpResponse response = new BufferedClientHttpResponse(execution.execute(request, body));
        final HttpHeaders headers = response.getHeaders();
		this.sessionIdCookies = headers.get(HttpHeaders.SET_COOKIE);
        return response;
    }

    /**
     * Wrapper around ClientHttpResponse, buffers the body so it can be read repeatedly (for logging & consuming the result).
     */
    private static class BufferedClientHttpResponse implements ClientHttpResponse {
        private final ClientHttpResponse response;
        private byte[] body;

		public BufferedClientHttpResponse(ClientHttpResponse _response) {
            this.response = _response;
        }

        @Override
        public HttpStatusCode getStatusCode() throws IOException {
            return this.response.getStatusCode();
        }

        @SuppressWarnings("removal")
		@Override
        public int getRawStatusCode() throws IOException {
            return this.response.getRawStatusCode();
        }

        @Override
        public String getStatusText() throws IOException {
            return this.response.getStatusText();
        }

        @Override
        public void close() {
        	this.response.close();
        }

        @Override
        public InputStream getBody() throws IOException {
            if (this.body == null) {
                try (final InputStream originalBody = this.response.getBody()) {
                	this.body = StreamUtils.copyToByteArray(originalBody);
                }
            }
            return new ByteArrayInputStream(this.body);
        }

        @Override
        public HttpHeaders getHeaders() {
            return this.response.getHeaders();
        }
    }
}
