package com.github.justincranford.springs.service.webauthn.credential.config;

import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.data.envers.repository.support.EnversRevisionRepositoryFactoryBean;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

import com.github.justincranford.springs.service.webauthn.credential.repository.CredentialOrm;
import com.github.justincranford.springs.service.webauthn.credential.repository.CredentialRepositoryOrm;
import com.github.justincranford.springs.service.webauthn.credential.repository.UserIdentityOrm;
import com.github.justincranford.springs.service.webauthn.credential.repository.UserIdentityRepositoryOrm;
import com.github.justincranford.springs.service.webauthn.credential.repository.converter.SetAuthenticatorTransportConverter;

@Configuration
@EntityScan(
	basePackageClasses = {CredentialOrm.class, UserIdentityOrm.class}
)
@EnableJpaRepositories(
	repositoryFactoryBeanClass = EnversRevisionRepositoryFactoryBean.class,
	basePackageClasses = {CredentialRepositoryOrm.class, UserIdentityRepositoryOrm.class}
)
@Import(value = {
	CredentialOrm.class,
	UserIdentityOrm.class,
	SetAuthenticatorTransportConverter.class
})
public class CredentialConfiguration {
	// do nothing
}
