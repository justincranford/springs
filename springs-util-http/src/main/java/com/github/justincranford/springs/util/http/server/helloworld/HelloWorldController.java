package com.github.justincranford.springs.util.http.server.helloworld;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@SuppressWarnings({"unused", "static-method" })
public class HelloWorldController {
    @GetMapping(
        value = { Constants.PATH },
        produces = { Constants.RESPONSE_CONTEXT_TYPE }
    )
    public String helloWorld() {
        return Constants.RESPONSE_BODY;
    }

    public static class Constants {
        public static final String PATH = "/helloworld";
        public static final String RESPONSE_BODY = "Hello world";
        public static final String RESPONSE_CONTEXT_TYPE = "plain/text; charset=UTF-8";
    }
}
