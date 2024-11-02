package com.github.justincranford.springs.authenticationorm.users.authentication.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
@SuppressWarnings({"nls", "static-method"})
public class RedirectController {
	@GetMapping("/")
    public String redirectToLogin() {
        return "redirect:/login";
    }
}
