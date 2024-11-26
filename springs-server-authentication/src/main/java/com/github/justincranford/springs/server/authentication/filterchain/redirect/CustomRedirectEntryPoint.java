package com.github.justincranford.springs.server.authentication.filterchain.redirect;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;

@RequiredArgsConstructor
@Slf4j
public class CustomRedirectEntryPoint implements AuthenticationEntryPoint {
    private final String redirectUrl;

    @Override
    public void commence(
        final HttpServletRequest request,
        final HttpServletResponse response,
        final AuthenticationException authenticationException
    ) throws IOException {
        log.info("Authentication exception", authenticationException);
        response.sendRedirect(this.redirectUrl);
    }
}
