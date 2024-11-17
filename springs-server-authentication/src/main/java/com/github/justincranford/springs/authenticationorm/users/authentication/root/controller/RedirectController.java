package com.github.justincranford.springs.authenticationorm.users.authentication.root.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
@SuppressWarnings({ "unused", "static-method" })
public class RedirectController {
//	@GetMapping("/")
//	public String redirectToLogin() {
//		return "redirect:/login";
//	}

    @GetMapping({ "/secure/home", "/secure/home/" })
    public String forwardToIndex() {
        return "forward:/secure/home/index.html";
    }
}
