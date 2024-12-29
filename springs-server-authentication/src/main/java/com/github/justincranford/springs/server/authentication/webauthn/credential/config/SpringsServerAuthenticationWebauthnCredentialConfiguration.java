package com.github.justincranford.springs.server.authentication.webauthn.credential.config;

import com.github.justincranford.springs.server.authentication.webauthn.credential.repository.PublicKeyCredentialOrm;
import com.github.justincranford.springs.server.authentication.webauthn.credential.repository.PublicKeyCredentialRepositoryOrm;
import com.github.justincranford.springs.server.authentication.webauthn.credential.service.PublicKeyCredentialRepositoryService;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.envers.repository.support.EnversRevisionRepositoryFactoryBean;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@Configuration
@EntityScan(
    basePackageClasses={PublicKeyCredentialOrm.class}
)
@EnableJpaRepositories(
    basePackageClasses = {PublicKeyCredentialRepositoryOrm.class},
    repositoryFactoryBeanClass = EnversRevisionRepositoryFactoryBean.class
)
@ComponentScan(
    basePackageClasses={
        PublicKeyCredentialRepositoryService.class
    }
)
public class SpringsServerAuthenticationWebauthnCredentialConfiguration {
}
