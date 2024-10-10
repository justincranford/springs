package com.github.justincranford.springs.service.webauthn.actions.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import com.github.justincranford.springs.service.webauthn.actions.controller.ActionsController;

@Configuration
@Import({ActionsController.class})
public class ActionsConfiguration {
	// do nothing
}
