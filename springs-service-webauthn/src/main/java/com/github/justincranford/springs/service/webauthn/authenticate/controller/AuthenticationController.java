package com.github.justincranford.springs.service.webauthn.authenticate.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.github.justincranford.springs.service.webauthn.authenticate.data.AuthenticationFinishClient;
import com.github.justincranford.springs.service.webauthn.authenticate.data.AuthenticationFinishServer;
import com.github.justincranford.springs.service.webauthn.authenticate.data.AuthenticationStartClient;
import com.github.justincranford.springs.service.webauthn.authenticate.data.AuthenticationStartServer;
import com.github.justincranford.springs.service.webauthn.authenticate.service.AuthenticationService;

import jakarta.annotation.Nonnull;

@RestController
@RequestMapping(value="/")
@SuppressWarnings({"nls"})
public class AuthenticationController {
	@Autowired
	private AuthenticationService authenticationService;

	@PostMapping(value={Constants.START, Constants.START + "/"}, consumes={Constants.JSON}, produces={Constants.JSON})
	public AuthenticationStartServer startAuthentication(@Nonnull @RequestBody final AuthenticationStartClient authenticationStartClient) {
		return this.authenticationService.start(authenticationStartClient);
	}

	@PostMapping(value={Constants.FINISH, Constants.FINISH + "/"}, consumes={Constants.JSON}, produces={Constants.JSON})
	public AuthenticationFinishServer finishAuthentication(@Nonnull @RequestBody final AuthenticationFinishClient authenticationResponse) {
		return this.authenticationService.finish(authenticationResponse);
	}

	public static class Constants {
		private static final String START  = "/api/v1/authenticate/start";
		private static final String FINISH = "/api/v1/authenticate/finish";
		private static final String JSON   = "application/json; charset=UTF-8";
	}
}