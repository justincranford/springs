package com.github.justincranford.springs.service.webauthn.register.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.github.justincranford.springs.service.webauthn.register.data.RegistrationClientStart;
import com.github.justincranford.springs.service.webauthn.register.data.RegistrationRequest;
import com.github.justincranford.springs.service.webauthn.register.data.RegistrationResponse;
import com.github.justincranford.springs.service.webauthn.register.data.RegistrationSuccess;
import com.github.justincranford.springs.service.webauthn.register.service.RegistrationService;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.constraints.NotEmpty;

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
	public RegistrationRequest startRegistration(
		@Nonnull @RequestBody final RegistrationClientStart registrationClientStart
	) {
		return this.registrationService.start(registrationClientStart);
	}

	@PostMapping(
		value={FinishConstants.PATH, FinishConstants.PATH + "/"},
		consumes={FinishConstants.CONSUMES},
		produces={FinishConstants.PRODUCES}
	)
	public RegistrationSuccess finishRegistration(
		@Nonnull @RequestBody final RegistrationResponse registrationResponse
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