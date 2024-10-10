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
public class ActionsController {
	@Autowired
	private ObjectMapper objectMapper;

	@GetMapping(value={"/api/v1/"})
	public String index(HttpServletRequest request) throws IOException {
		final ActionsResponse indexResponse = new ActionsResponse(request.getRequestURL().toString());
		return this.objectMapper.writeValueAsString(indexResponse);
	}
}