package com.github.justincranford.springs.util.security.passwords.generator;

import com.github.justincranford.springs.util.security.passwords.constraints.PasswordConstraints;
import com.github.justincranford.springs.util.security.passwords.constraints.PasswordConstraintsUtil;
import com.github.justincranford.springs.util.security.passwords.properties.SpringsUtilSecurityPasswordsProperties;
import com.github.justincranford.springs.util.security.passwords.properties.SpringsUtilSecurityPasswordsProperties.Clients;
import com.github.justincranford.springs.util.security.passwords.properties.SpringsUtilSecurityPasswordsProperties.Defaults;
import com.github.justincranford.springs.util.security.passwords.properties.SpringsUtilSecurityPasswordsProperties.Servers;
import com.github.justincranford.springs.util.security.passwords.properties.SpringsUtilSecurityPasswordsProperties.Users;
import com.github.justincranford.springs.util.security.passwords.validator.PasswordValidator;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
@SuppressWarnings({ "unused" })
public class PasswordGeneratorConfiguration {
    @Autowired
    private final SpringsUtilSecurityPasswordsProperties springsUtilSecurityPasswordsProperties;

    @Bean
    public PasswordGenerator usersPasswordGenerator() {
        return PasswordGenerator.create(usersPasswordContraints());
    }

    private PasswordConstraints usersPasswordContraints() {
        final Users usersProperties = this.springsUtilSecurityPasswordsProperties.getUsers();
        return PasswordConstraintsUtil.proxy(usersProperties);
    }

    @Bean
    public PasswordValidator usersPasswordValidator() {
        return PasswordValidator.create(usersPasswordContraints());
    }

    @Bean
    public PasswordGenerator clientsPasswordGenerator() {
        return PasswordGenerator.create(clientsPasswordConstraints());
    }

    private PasswordConstraints clientsPasswordConstraints() {
        final Clients clientsProperties = this.springsUtilSecurityPasswordsProperties.getClients();
        return PasswordConstraintsUtil.proxy(clientsProperties);
    }

    @Bean
    public PasswordValidator clientsPasswordValidator() {
        return PasswordValidator.create(clientsPasswordConstraints());
    }

    @Bean
    public PasswordGenerator serversPasswordGenerator() {
        return PasswordGenerator.create(serverPasswordContraints());
    }

    private PasswordConstraints serverPasswordContraints() {
        final Servers serversProperties = this.springsUtilSecurityPasswordsProperties.getServers();
        return PasswordConstraintsUtil.proxy(serversProperties);
    }

    @Bean
    public PasswordValidator serversPasswordValidator() {
        return PasswordValidator.create(serverPasswordContraints());
    }

    @Bean
    public PasswordGenerator defaultsPasswordGenerator() {
        return PasswordGenerator.create(defaultsPasswordContraints());
    }

    private PasswordConstraints defaultsPasswordContraints() {
        final Defaults defaultsProperties = this.springsUtilSecurityPasswordsProperties.getDefaults();
        return PasswordConstraintsUtil.proxy(defaultsProperties);
    }

    @Bean
    public PasswordValidator defaultsPasswordValidator() {
        return PasswordValidator.create(defaultsPasswordContraints());
    }
}
