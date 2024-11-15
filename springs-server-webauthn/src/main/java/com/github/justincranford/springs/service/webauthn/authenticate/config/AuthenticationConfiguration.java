package com.github.justincranford.springs.service.webauthn.authenticate.config;

import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.data.envers.repository.support.EnversRevisionRepositoryFactoryBean;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

import com.github.justincranford.springs.service.webauthn.authenticate.controller.AuthenticationController;
import com.github.justincranford.springs.service.webauthn.authenticate.repository.AuthenticationOrm;
import com.github.justincranford.springs.service.webauthn.authenticate.repository.AuthenticationRepositoryOrm;
import com.github.justincranford.springs.service.webauthn.authenticate.repository.PublicKeyCredentialRequestOptionsConverter;
import com.github.justincranford.springs.service.webauthn.authenticate.service.AuthenticationService;

@Configuration
@EntityScan(
	basePackageClasses = {AuthenticationOrm.class}
)
@EnableJpaRepositories(
	repositoryFactoryBeanClass = EnversRevisionRepositoryFactoryBean.class,
	basePackageClasses = {AuthenticationRepositoryOrm.class}
)
@Import({
	AuthenticationOrm.class,
	AuthenticationController.class,
	AuthenticationService.class,
	PublicKeyCredentialRequestOptionsConverter.class
})
public class AuthenticationConfiguration {
	// empty
}
