package com.github.justincranford.springs.service.webauthn.authentication.service;

import java.net.MalformedURLException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.justincranford.springs.service.webauthn.authentication.data.AuthenticationRequest;
import com.github.justincranford.springs.service.webauthn.authentication.data.AuthenticationResponse;
import com.github.justincranford.springs.service.webauthn.authentication.data.AuthenticationSuccess;
import com.github.justincranford.springs.service.webauthn.authentication.repository.AuthenticationRepositoryOrm;
import com.github.justincranford.springs.service.webauthn.credential.repository.CredentialRepositoryOrm;
import com.yubico.webauthn.RelyingParty;

import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
@SuppressWarnings({"nls", "deprecation", "unused", "static-method"})
public class AuthenticationService {
	@Autowired
	private ObjectMapper objectMapper;
	@Autowired
	private RelyingParty relyingParty;
	@Autowired
	private AuthenticationRepositoryOrm authenticationRepositoryOrm;
	@Autowired
	private CredentialRepositoryOrm credentialRepositoryOrm;

	public AuthenticationRequest start(
		final String username,
		final String displayName,
		final String credentialNickname,
		final String requestUrl
	) throws MalformedURLException, JsonProcessingException {
		return null;
	}

	public AuthenticationSuccess finish(final AuthenticationResponse AuthenticationResponse) {
		return null;
	}
}
