package com.github.justincranford.springs.service.webauthn.register.config;

import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.data.envers.repository.support.EnversRevisionRepositoryFactoryBean;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

import com.github.justincranford.springs.service.webauthn.credential.repository.converter.SetAuthenticatorTransportConverter;
import com.github.justincranford.springs.service.webauthn.register.controller.RegisterController;
import com.github.justincranford.springs.service.webauthn.register.repository.PublicKeyCredentialCreationOptionsConverter;
import com.github.justincranford.springs.service.webauthn.register.repository.RegistrationOrm;
import com.github.justincranford.springs.service.webauthn.register.repository.RegistrationRepositoryOrm;
import com.github.justincranford.springs.service.webauthn.register.service.RegistrationService;

@Configuration
@EntityScan(
	basePackageClasses = {RegistrationOrm.class}
)
@EnableJpaRepositories(
	repositoryFactoryBeanClass = EnversRevisionRepositoryFactoryBean.class,
	basePackageClasses = {RegistrationRepositoryOrm.class}
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
