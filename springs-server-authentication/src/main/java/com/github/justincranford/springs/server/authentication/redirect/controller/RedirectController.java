package com.github.justincranford.springs.server.authentication.redirect.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
@SuppressWarnings({ "static-method" })
public class RedirectController {
//	@GetMapping("/")
//	public String redirectToLogin() {
//		return "redirect:/login";
//	}

	@GetMapping({"/secure/home", "/secure/home/"})
	public String forwardToIndex() {
		return "forward:/secure/home/index.html";
	}
}
