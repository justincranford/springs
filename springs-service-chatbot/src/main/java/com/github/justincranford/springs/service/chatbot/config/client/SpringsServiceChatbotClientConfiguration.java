package com.github.justincranford.springs.service.chatbot.config.client;

import com.github.justincranford.springs.service.chatbot.client.SpringsServiceChatbotClient;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpRequest;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.util.StreamUtils;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;

@Configuration
@ComponentScan(basePackageClasses = { SpringsServiceChatbotClient.class })
@Slf4j
@SuppressWarnings({"unused", "static-method" })
public class SpringsServiceChatbotClientConfiguration {
    @Bean
    public RestTemplate restTemplate() {
        final RestTemplate restTemplate = new RestTemplate();
        restTemplate.getInterceptors().add(new LoggingInterceptor());
        restTemplate.setErrorHandler(new DefaultResponseErrorHandler());
        return restTemplate;
    }

    public static class LoggingInterceptor implements ClientHttpRequestInterceptor {
        private final AtomicInteger requestNumberSequence = new AtomicInteger(1);

        @Override
        public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution) throws IOException {
            int requestNumber = this.requestNumberSequence.getAndIncrement();
            logRequest(requestNumber, request, body);
            ClientHttpResponse response = execution.execute(request, body);
            response = new BufferedClientHttpResponse(response);
            logResponse(requestNumber, response);
            return response;
        }

        private void logRequest(int requestNumber, HttpRequest request, byte[] body) {
            if (log.isDebugEnabled()) {
                String prefix = requestNumber + " > ";
                log.debug("{} Request: {} {}", prefix, request.getMethod(), request.getURI());
                log.debug("{} Headers: {}", prefix, request.getHeaders());
                if (body.length > 0) {
                    log.debug("{} Body: \n{}", prefix, new String(body, StandardCharsets.UTF_8));
                }
            }
        }

        private void logResponse(int requestNumber, ClientHttpResponse response) throws IOException {
            if (log.isDebugEnabled()) {
                String prefix = requestNumber + " < ";
                log.debug("{} Response: {} {}", prefix, response.getStatusCode(), response.getStatusText());
                log.debug("{} Headers: {}", prefix, response.getHeaders());
                try (final InputStream originalBody = response.getBody()) {
                    String body = StreamUtils.copyToString(originalBody, StandardCharsets.UTF_8);
                    if (!body.isEmpty()) {
                        log.debug("{} Body: \n{}", prefix, body);
                    }
                }
            }
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
}
