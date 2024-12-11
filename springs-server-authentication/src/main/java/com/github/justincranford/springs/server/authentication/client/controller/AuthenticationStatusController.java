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
	@GetMapping({"/api/v1/authenticate/status", "/api/v1/authenticate/status/"})
	public ResponseEntity<String> status() {
		final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication == null) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Null authentication");
		} else if (authentication instanceof AnonymousAuthenticationToken) {
			return ResponseEntity.ok().body("Authenticated as anonymous");
		} else if (!authentication.isAuthenticated()) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Non-null authentication, but unauthenticated: " + authentication);
		}
		return ResponseEntity.ok().body("Authenticated as " + authentication.getName());
	}
}
