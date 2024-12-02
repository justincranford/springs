package com.github.justincranford.springs.server.authentication.client.controller;

import com.github.justincranford.springs.server.authentication.client.service.JwtIssuerService;
import com.github.justincranford.springs.server.authentication.client.token.ClientNameSecretAuthenticatedToken;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWT;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
@SuppressWarnings({"static-method"})
@Slf4j
public class JwtIssuerController {
	@Autowired
	private JwtIssuerService jwtIssuerService;

	@PostMapping({"/v1/api/authenticate/jwt", "/v1/api/authenticate/jwt/"})
	public ResponseEntity<String> jwt() throws JOSEException {
		final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication instanceof ClientNameSecretAuthenticatedToken clientNameSecretAuthenticatedToken) {
			final JWT jwt = this.jwtIssuerService.issue(clientNameSecretAuthenticatedToken);
			return ResponseEntity.ok().body(jwt.serialize());
		}
		return ResponseEntity.badRequest().body("Unsupported authentication " + authentication.getClass().getCanonicalName());
	}
}
