package com.github.justincranford.springs.service.webauthn.authentication.controller;

import java.net.MalformedURLException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.justincranford.springs.service.webauthn.authentication.data.AuthenticationRequest;
import com.github.justincranford.springs.service.webauthn.authentication.data.AuthenticationResponse;
import com.github.justincranford.springs.service.webauthn.authentication.data.AuthenticationSuccess;
import com.github.justincranford.springs.service.webauthn.authentication.service.AuthenticationService;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping(value="/")
@Slf4j
@SuppressWarnings({"nls"})
public class AuthenticationController {
	@Autowired
	private ObjectMapper objectMapper;
	@Autowired
	private AuthenticationService authenticationService;

	@PostMapping(value={"/api/v1/authenticate", "/api/v1/authenticate/"},consumes={"application/x-www-form-urlencoded"},produces={"application/json"})
	public AuthenticationRequest startAuthentication(
		final HttpServletRequest request,
		@Nonnull  @RequestParam(required=true)  final String  username,
		@Nonnull  @RequestParam(required=true)  final String  displayName,
		@Nullable @RequestParam(required=false) final String  credentialNickname,
		@Nonnull  @RequestParam(required=true)  final String  sessionToken,
		@Nullable @RequestParam(required=false) final Boolean requireResidentKey
	) throws JsonProcessingException, MalformedURLException {
		log.info("username: {}, displayName: {}, credentialNickname: {}, sessionToken: {}, requireResidentKey: {}",
			username,
			displayName,
			credentialNickname,
			sessionToken,
			requireResidentKey
		);
		return this.authenticationService.start(username, displayName, credentialNickname, request.getRequestURL().toString());
	}

	// /api/v1/register/finish
	@PostMapping(
		value={"/api/v1/authenticate/finish","/api/v1/authenticate/finish/"},
		consumes={"text/plain;charset=UTF-8"},
		produces={"application/json"}
	)
	public AuthenticationSuccess finishAuthentication(@RequestBody final String responseString) throws JsonMappingException, JsonProcessingException {
		log.info("responseString: {}", responseString);

		final AuthenticationResponse authenticationResponse = this.objectMapper.readValue(responseString, AuthenticationResponse.class);
		log.info("response: {}", authenticationResponse);

		return this.authenticationService.finish(authenticationResponse);
	}
}