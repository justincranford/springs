package com.github.justincranford.springs.server.webauthn.register.config;

import com.github.justincranford.springs.server.webauthn.credential.repository.converter.SetAuthenticatorTransportConverter;
import com.github.justincranford.springs.server.webauthn.register.controller.RegisterController;
import com.github.justincranford.springs.server.webauthn.register.repository.PublicKeyCredentialCreationOptionsConverter;
import com.github.justincranford.springs.server.webauthn.register.repository.RegistrationOrm;
import com.github.justincranford.springs.server.webauthn.register.repository.RegistrationRepositoryOrm;
import com.github.justincranford.springs.server.webauthn.register.service.RegistrationService;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.data.envers.repository.support.EnversRevisionRepositoryFactoryBean;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@Configuration
@EntityScan(
    basePackageClasses = { RegistrationOrm.class }
)
@EnableJpaRepositories(
    repositoryFactoryBeanClass = EnversRevisionRepositoryFactoryBean.class,
    basePackageClasses = { RegistrationRepositoryOrm.class }
)
@Import({
    RegistrationOrm.class,
    RegisterController.class,
    RegistrationService.class,
    SetAuthenticatorTransportConverter.class,
    PublicKeyCredentialCreationOptionsConverter.class
})
public class RegistrationConfiguration {
    // empty
}
