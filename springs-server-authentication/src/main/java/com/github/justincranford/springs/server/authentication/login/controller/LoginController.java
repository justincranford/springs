package com.github.justincranford.springs.server.authentication.login.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class LoginController {
    @GetMapping("/login")
    public String loginPage(@RequestParam(value = "logout", required = false) String logout,
                            @RequestParam(value = "expired", required = false) String expired,
                            Model model) {
        if (logout != null) {
            model.addAttribute("message", "You have been logged out successfully.");
        }
        if (expired != null) {
            model.addAttribute("message", "Your session has expired. Please log in again.");
        }
        return "login"; // Maps to `login.html` in `src/main/resources/templates`
    }
}
