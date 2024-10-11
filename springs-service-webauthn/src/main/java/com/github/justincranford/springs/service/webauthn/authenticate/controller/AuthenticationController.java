package com.github.justincranford.springs.service.webauthn.authenticate.controller;

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
import com.github.justincranford.springs.service.webauthn.authenticate.data.AuthenticationRequest;
import com.github.justincranford.springs.service.webauthn.authenticate.data.AuthenticationResponse;
import com.github.justincranford.springs.service.webauthn.authenticate.data.AuthenticationSuccess;
import com.github.justincranford.springs.service.webauthn.authenticate.service.AuthenticationService;

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

	@PostMapping(
		value={"/api/v1/authenticate", "/api/v1/authenticate/"},
		consumes={"application/x-www-form-urlencoded"},
		produces={"application/json"}
	)
	public AuthenticationRequest startAuthentication(
		final HttpServletRequest request,
		@Nullable @RequestParam(required=false) final String username
	) throws JsonProcessingException, MalformedURLException {
		return this.authenticationService.start(username, request.getRequestURL().toString());
	}

	@PostMapping(
		value={"/api/v1/authenticate/finish","/api/v1/authenticate/finish/"},
		consumes={"text/plain;charset=UTF-8"},
		produces={"application/json"}
	)
	public AuthenticationSuccess finishAuthentication(@RequestBody final String responseJson) throws JsonMappingException, JsonProcessingException {
		log.info("responseString: {}", responseJson);

		final AuthenticationResponse authenticationResponse = this.objectMapper.readValue(responseJson, AuthenticationResponse.class);
		log.info("authenticationResponse: {}", authenticationResponse);

		return this.authenticationService.finish(authenticationResponse);
	}
}