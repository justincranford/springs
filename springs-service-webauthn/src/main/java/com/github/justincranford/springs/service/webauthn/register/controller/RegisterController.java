package com.github.justincranford.springs.service.webauthn.register.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.github.justincranford.springs.service.webauthn.register.data.RegistrationFinishClient;
import com.github.justincranford.springs.service.webauthn.register.data.RegistrationStartClient;
import com.github.justincranford.springs.service.webauthn.register.data.RegistrationFinishServer;
import com.github.justincranford.springs.service.webauthn.register.data.RegistrationStartServer;
import com.github.justincranford.springs.service.webauthn.register.service.RegistrationService;

import jakarta.annotation.Nonnull;

@RestController
@RequestMapping(value="/")
@SuppressWarnings({"nls"})
public class RegisterController {
	@Autowired
	private RegistrationService registrationService;

	@PostMapping(value={Constants.START, Constants.START + "/"}, consumes={Constants.JSON}, produces={Constants.JSON})
	public RegistrationStartServer startRegistration(@Nonnull @RequestBody final RegistrationStartClient registrationStartClient) {
		return this.registrationService.start(registrationStartClient);
	}

	@PostMapping(value={Constants.FINISH, Constants.FINISH + "/"}, consumes={Constants.JSON}, produces={Constants.JSON})
	public RegistrationFinishServer finishRegistration(@Nonnull @RequestBody final RegistrationFinishClient registrationResponse) {
		return this.registrationService.finish(registrationResponse);
	}

	public static class Constants {
		private static final String START  = "/api/v1/register/start";
		private static final String FINISH = "/api/v1/register/finish";
		private static final String JSON   = "application/json; charset=UTF-8";
	}
}