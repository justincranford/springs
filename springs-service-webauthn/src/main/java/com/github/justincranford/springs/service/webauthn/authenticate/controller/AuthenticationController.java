package com.github.justincranford.springs.service.webauthn.authenticate.controller;

import java.net.MalformedURLException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.github.justincranford.springs.service.webauthn.authenticate.data.AuthenticationRequest;
import com.github.justincranford.springs.service.webauthn.authenticate.data.AuthenticationResponse;
import com.github.justincranford.springs.service.webauthn.authenticate.data.AuthenticationSuccess;
import com.github.justincranford.springs.service.webauthn.authenticate.service.AuthenticationService;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import jakarta.servlet.http.HttpServletRequest;

@RestController
@RequestMapping(value="/")
@SuppressWarnings({"nls"})
public class AuthenticationController {
	@Autowired
	private AuthenticationService authenticationService;

	@PostMapping(
		value={StartConstants.PATH, StartConstants.PATH + "/"},
		consumes={StartConstants.CONSUMES},
		produces={StartConstants.PRODUCES}
	)
	public AuthenticationRequest startAuthentication(
		@Nonnull                                final HttpServletRequest request,
		@Nullable @RequestParam(required=false) final String username
	) throws JsonProcessingException, MalformedURLException {
		return this.authenticationService.start(username, request.getRequestURL().toString());
	}

	@PostMapping(
		value={FinishConstants.PATH, FinishConstants.PATH + "/"},
		consumes={FinishConstants.CONSUMES},
		produces={FinishConstants.PRODUCES}
	)
	public AuthenticationSuccess finishAuthentication(
		@Nonnull @RequestBody final AuthenticationResponse authenticationResponse
	) {
		return this.authenticationService.finish(authenticationResponse);
	}

	public static class StartConstants {
		private static final String PATH     = "/api/v1/authenticate";
		private static final String CONSUMES = "application/x-www-form-urlencoded; charset=UTF-8";
		private static final String PRODUCES = "application/json; charset=UTF-8";
	}

	public static class FinishConstants {
		private static final String PATH     = "/api/v1/authenticate/finish";
		private static final String CONSUMES = "application/json; charset=UTF-8";
		private static final String PRODUCES = "application/json; charset=UTF-8";
	}
}