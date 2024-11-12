package com.github.justincranford.springs.service.http.server;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class RedirectToLoginConfigurer implements WebMvcConfigurer {
	@Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addRedirectViewController("/", "/login");
        registry.addRedirectViewController("/index.html", "/login");
        registry.addRedirectViewController("/home.html", "/login");
    }
}
