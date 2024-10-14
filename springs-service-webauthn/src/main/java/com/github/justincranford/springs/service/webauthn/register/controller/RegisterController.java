package com.github.justincranford.springs.service.webauthn.register.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.github.justincranford.springs.service.webauthn.register.data.RegistrationClientFinish;
import com.github.justincranford.springs.service.webauthn.register.data.RegistrationClientStart;
import com.github.justincranford.springs.service.webauthn.register.data.RegistrationServerFinish;
import com.github.justincranford.springs.service.webauthn.register.data.RegistrationServerStart;
import com.github.justincranford.springs.service.webauthn.register.service.RegistrationService;

import jakarta.annotation.Nonnull;

@RestController
@RequestMapping(value="/")
@SuppressWarnings({"nls"})
public class RegisterController {
	@Autowired
	private RegistrationService registrationService;

	@PostMapping(
		value={StartConstants.PATH, StartConstants.PATH + "/"},
		consumes={StartConstants.CONSUMES},
		produces={StartConstants.PRODUCES}
	)
	public RegistrationServerStart startRegistration(
		@Nonnull @RequestBody final RegistrationClientStart registrationClientStart
	) {
		return this.registrationService.start(registrationClientStart);
	}

	@PostMapping(
		value={FinishConstants.PATH, FinishConstants.PATH + "/"},
		consumes={FinishConstants.CONSUMES},
		produces={FinishConstants.PRODUCES}
	)
	public RegistrationServerFinish finishRegistration(
		@Nonnull @RequestBody final RegistrationClientFinish registrationResponse
	) {
		return this.registrationService.finish(registrationResponse);
	}

	public static class StartConstants {
		private static final String PATH     = "/api/v1/register/start";
		private static final String CONSUMES = "application/json; charset=UTF-8";
		private static final String PRODUCES = "application/json; charset=UTF-8";
	}

	public static class FinishConstants {
		private static final String PATH     = "/api/v1/register/finish";
		private static final String CONSUMES = "application/json; charset=UTF-8";
		private static final String PRODUCES = "application/json; charset=UTF-8";
	}
}