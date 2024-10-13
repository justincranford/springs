package com.github.justincranford.springs.service.webauthn.actions.controller;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.justincranford.springs.service.webauthn.actions.data.ActionsResponse;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping(value="/")
@Slf4j
@SuppressWarnings({"nls", "static-method"})
public class ActionsController {
	@Autowired
	private ObjectMapper objectMapper;

	@GetMapping(
		value={"/api/v1", "/api/v1/"},
		produces={"application/json"}
	)
	public ActionsResponse actions(HttpServletRequest request) throws IOException {
		final ActionsResponse actionsResponse = new ActionsResponse(request.getRequestURL().toString());
		final String actionsResponseJson = this.objectMapper.writeValueAsString(actionsResponse);//.replace("\"allowCredentials\":null,", "");
		log.info("actionsResponseJson: {}", actionsResponseJson);
		return actionsResponse;
	}
}