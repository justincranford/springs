package com.github.justincranford.springs.service.http.server;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@SuppressWarnings({"nls", "static-method"})
public class HelloWorldController {
	@GetMapping
	@RequestMapping(HelloWorldController.Constants.PATH)
	public String helloWorld() {
		return HelloWorldController.Constants.RESPONSE_BODY;
	}

	public static class Constants {
		public static final String PATH = "/helloworld";
		public static final String RESPONSE_BODY = "Hello world";

	}
}
