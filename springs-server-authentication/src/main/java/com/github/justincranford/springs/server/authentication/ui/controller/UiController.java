package com.github.justincranford.springs.server.authentication.ui.controller;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

@Controller
@Slf4j
@SuppressWarnings({"unused"})
public class UiController {
    @GetMapping({"/login", "/login/"})
    public ModelAndView loginPage(final HttpServletRequest request,
        @RequestParam(value="logout",  required=false) String logout,
        @RequestParam(value="error",   required=false) String error,
        @RequestParam(value="expired", required=false) String expired
    ) {
        final CsrfToken csrfToken = (CsrfToken) request.getAttribute(CsrfToken.class.getName());

        final ModelAndView modelAndView = new ModelAndView("login");
        modelAndView.addObject("_csrf", csrfToken);
        if (logout != null) {
            modelAndView.addObject("message", "You have been logged out successfully. Please log in again.");
        } else if (expired != null) {
            modelAndView.addObject("message", "Your session has expired. Please log in again.");
        } else {
            modelAndView.addObject("message", "Welcome! Please log in!");
        }
        if (error != null) {
            modelAndView.addObject("error", "There was an error. Please log in again.");
        }
        return modelAndView;
    }

    @GetMapping({"/secure/home", "/secure/home/"})
    public ModelAndView home(final HttpServletRequest request) {
        final CsrfToken csrfToken = (CsrfToken) request.getAttribute(CsrfToken.class.getName());

        final ModelAndView modelAndView = new ModelAndView("secure/home/index");
        modelAndView.addObject("message", "Welcome to the secure home page!");
        modelAndView.addObject("_csrf", csrfToken);
        return modelAndView;
    }
}
