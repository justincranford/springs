package com.github.justincranford.springs.service.webauthn.register.controller;

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
import com.github.justincranford.springs.service.webauthn.register.data.RegistrationRequest;
import com.github.justincranford.springs.service.webauthn.register.data.RegistrationResponse;
import com.github.justincranford.springs.service.webauthn.register.data.RegistrationSuccess;
import com.github.justincranford.springs.service.webauthn.register.service.RegistrationService;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping(value="/")
@Slf4j
@SuppressWarnings({"nls"})
public class RegisterController {
	@Autowired
	private ObjectMapper objectMapper;
	@Autowired
	private RegistrationService registrationService;

	@PostMapping(
		value={"/api/v1/register", "/api/v1/register/"},
		consumes={"application/x-www-form-urlencoded"},
		produces={"application/json"}
	)
	public RegistrationRequest startRegistration(
		final HttpServletRequest request,
		@Nonnull  @RequestParam(required=true)  final String  username,
		@Nonnull  @RequestParam(required=true)  final String  displayName,
		@Nullable @RequestParam(required=false) final String  credentialNickname,
		@Nonnull  @RequestParam(required=true)  final String  sessionToken,
		@Nullable @RequestParam(required=false) final Boolean requireResidentKey
	) throws JsonProcessingException, MalformedURLException {
		final RegistrationRequest registrationRequest = this.registrationService.start(username, displayName, credentialNickname, sessionToken, requireResidentKey, request.getRequestURL().toString());
		final String registrationRequestJson = this.objectMapper.writeValueAsString(registrationRequest);
		log.info("registrationRequestJson: {}", registrationRequestJson);
		return registrationRequest;
	}

	// /api/v1/register/finish
	@PostMapping(
		value={"/api/v1/register/finish","/api/v1/register/finish/"},
		consumes={"text/plain;charset=UTF-8"},
		produces={"application/json"}
	)
	public RegistrationSuccess finishRegistration(@RequestBody final String registrationResponseJson) throws JsonMappingException, JsonProcessingException {
		log.info("registrationResponseJson: {}", registrationResponseJson);

		final RegistrationResponse registrationResponse = this.objectMapper.readValue(registrationResponseJson, RegistrationResponse.class);
		log.info("registrationResponse: {}", registrationResponse);

		return this.registrationService.finish(registrationResponse);
	}
}