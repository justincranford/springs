package com.github.justincranford.springs.server.authentication.client.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
@SuppressWarnings({"static-method"})
@Slf4j
public class AuthenticationStatusController {
	@GetMapping({"/v1/api/authenticate/status", "/v1/api/authenticate/status/"})
	public ResponseEntity<String> status() {
		final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication == null) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Not authenticated");
		} else if (authentication instanceof AnonymousAuthenticationToken) {
			return ResponseEntity.ok().body("Authenticated as anonymous");
		} else if (authentication.isAuthenticated()) {
			return ResponseEntity.ok().body("Authenticated as " + authentication.getName());
		}
		log.error("Unexpected authentication state: {}", authentication);
		return ResponseEntity.internalServerError().body("Unexpected authentication state");
	}
}
