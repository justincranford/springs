package com.github.justincranford.springs.server.webauthn.authenticate.controller;

import com.github.justincranford.springs.server.webauthn.authenticate.data.AuthenticationFinishClient;
import com.github.justincranford.springs.server.webauthn.authenticate.data.AuthenticationFinishServer;
import com.github.justincranford.springs.server.webauthn.authenticate.data.AuthenticationStartClient;
import com.github.justincranford.springs.server.webauthn.authenticate.data.AuthenticationStartServer;
import com.github.justincranford.springs.server.webauthn.authenticate.service.AuthenticationService;
import jakarta.annotation.Nonnull;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/")
@SuppressWarnings({"unused"})
public class AuthenticationController {
    @Autowired
    private AuthenticationService authenticationService;

    @PostMapping(value = { Constants.START, Constants.START + "/" }, consumes = { Constants.JSON }, produces = { Constants.JSON })
    public AuthenticationStartServer startAuthentication(@Nonnull @RequestBody final AuthenticationStartClient authenticationStartClient) {
        return this.authenticationService.start(authenticationStartClient);
    }

    @PostMapping(value = { Constants.FINISH, Constants.FINISH + "/" }, consumes = { Constants.JSON }, produces = { Constants.JSON })
    public AuthenticationFinishServer finishAuthentication(@Nonnull @RequestBody final AuthenticationFinishClient authenticationResponse, @Nonnull final HttpSession session) {
        return this.authenticationService.finish(authenticationResponse, session);
    }

    @GetMapping(value = { Constants.STATUS, Constants.STATUS + "/" }, produces = { Constants.JSON })
    public String statusAuthentication(@Nonnull HttpSession session) {
        return this.authenticationService.status(session);
    }

    public static class Constants {
        private static final String START = "/api/v1/authenticate/start";
        private static final String FINISH = "/api/v1/authenticate/finish";
        private static final String STATUS = "/api/v1/authenticate/status";
        private static final String JSON = "application/json; charset=UTF-8";
    }
}
