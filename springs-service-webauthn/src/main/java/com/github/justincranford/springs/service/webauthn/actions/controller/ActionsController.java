package com.github.justincranford.springs.service.webauthn.actions.controller;

import java.io.IOException;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.github.justincranford.springs.service.webauthn.actions.data.ActionsResponse;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping(value="/")
@Slf4j
@SuppressWarnings({"static-method"})
public class ActionsController {
	@GetMapping(
		value={"/api/v1", "/api/v1/"},
		produces={"application/json"}
	)
	public ActionsResponse actions(HttpServletRequest request) throws IOException {
		return new ActionsResponse(request.getRequestURL().toString());
	}
}