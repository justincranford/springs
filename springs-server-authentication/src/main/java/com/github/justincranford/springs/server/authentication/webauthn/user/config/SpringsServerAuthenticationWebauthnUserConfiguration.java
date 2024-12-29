package com.github.justincranford.springs.server.authentication.webauthn.user.config;

import com.github.justincranford.springs.server.authentication.webauthn.user.service.PublicKeyCredentialUserEntityRepositoryService;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

@Configuration
@ComponentScan(
    basePackageClasses={PublicKeyCredentialUserEntityRepositoryService.class}
)
public class SpringsServerAuthenticationWebauthnUserConfiguration {
}
