package com.github.justincranford.springs.service.webauthn.credential.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.data.envers.repository.support.EnversRevisionRepositoryFactoryBean;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

import com.github.justincranford.springs.service.webauthn.credential.repository.CredentialOrm;
import com.github.justincranford.springs.service.webauthn.credential.repository.CredentialRepositoryFacade;
import com.github.justincranford.springs.service.webauthn.credential.repository.CredentialRepositoryOrm;
import com.github.justincranford.springs.service.webauthn.credential.repository.UserIdentityOrm;
import com.github.justincranford.springs.service.webauthn.credential.repository.UserIdentityRepositoryOrm;
import com.github.justincranford.springs.service.webauthn.credential.repository.converter.SetAuthenticatorTransportConverter;
import com.github.justincranford.springs.service.webauthn.register.service.RegistrationService;

@Configuration
@EnableJpaRepositories(
	basePackageClasses = {CredentialRepositoryOrm.class, UserIdentityRepositoryOrm.class},
	repositoryFactoryBeanClass = EnversRevisionRepositoryFactoryBean.class
)
@Import(value = {
	RegistrationService.class,
	CredentialRepositoryFacade.class,
	CredentialOrm.class,
	UserIdentityOrm.class,
	SetAuthenticatorTransportConverter.class
})
public class CredentialConfiguration {
	// do nothing
}
