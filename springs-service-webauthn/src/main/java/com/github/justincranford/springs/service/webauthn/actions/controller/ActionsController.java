package com.github.justincranford.springs.service.webauthn.actions.controller;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.github.justincranford.springs.service.webauthn.actions.data.ActionsResponse;
import com.github.justincranford.springs.util.json.config.PrettyJson;

import jakarta.annotation.Nonnull;
import jakarta.servlet.http.HttpServletRequest;

@RestController
@RequestMapping(value="/")
@SuppressWarnings({"nls"})
public class ActionsController {
	@Autowired
	private PrettyJson prettyJson;

	// /api/v1
	@GetMapping(
		value={Constants.PATH, Constants.PATH + "/"},
		produces={Constants.PRODUCES}
	)
	public ActionsResponse actions(
		@Nonnull HttpServletRequest request
	) throws IOException {
		final String requestUrl = request.getRequestURL().toString();
		return this.prettyJson.log(new ActionsResponse(requestUrl));
	}

	public static class Constants {
		private static final String PATH = "/api/v1";
		private static final String PRODUCES = "application/json; charset=UTF-8";
	}
}