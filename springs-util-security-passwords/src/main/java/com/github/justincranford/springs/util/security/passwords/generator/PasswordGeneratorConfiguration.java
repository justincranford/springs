package com.github.justincranford.springs.util.security.passwords.generator;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.github.justincranford.springs.util.security.passwords.constraints.PasswordConstraints;
import com.github.justincranford.springs.util.security.passwords.constraints.PasswordConstraintsUtil;
import com.github.justincranford.springs.util.security.passwords.properties.SpringsUtilSecurityPasswordsProperties;
import com.github.justincranford.springs.util.security.passwords.properties.SpringsUtilSecurityPasswordsProperties.Clients;
import com.github.justincranford.springs.util.security.passwords.properties.SpringsUtilSecurityPasswordsProperties.Defaults;
import com.github.justincranford.springs.util.security.passwords.properties.SpringsUtilSecurityPasswordsProperties.Servers;
import com.github.justincranford.springs.util.security.passwords.properties.SpringsUtilSecurityPasswordsProperties.Users;
import com.github.justincranford.springs.util.security.passwords.validator.PasswordValidator;

import lombok.RequiredArgsConstructor;

@Configuration
@RequiredArgsConstructor
public class PasswordGeneratorConfiguration {
	@Autowired
	private final SpringsUtilSecurityPasswordsProperties springsUtilSecurityPasswordsProperties;

	@Bean
	public PasswordGenerator usersPasswordGenerator() {
		return PasswordGenerator.create(usersPasswordContraints());
	}
	@Bean
	public PasswordValidator usersPasswordValidator() {
		return PasswordValidator.create(usersPasswordContraints());
	}

	@Bean
	public PasswordGenerator clientsPasswordGenerator() {
		return PasswordGenerator.create(clientsPasswordConstraints());
	}
	@Bean
	public PasswordValidator clientsPasswordValidator() {
		return PasswordValidator.create(clientsPasswordConstraints());
	}

	@Bean
	public PasswordGenerator serversPasswordGenerator() {
		return PasswordGenerator.create(serverPasswordContraints());
	}
	@Bean
	public PasswordValidator serversPasswordValidator() {
		return PasswordValidator.create(serverPasswordContraints());
	}

	@Bean
	public PasswordGenerator defaultsPasswordGenerator() {
		return PasswordGenerator.create(defaultsPasswordContraints());
	}
	@Bean
	public PasswordValidator defaultsPasswordValidator() {
		return PasswordValidator.create(defaultsPasswordContraints());
	}

	private PasswordConstraints usersPasswordContraints() {
		final Users usersProperties = this.springsUtilSecurityPasswordsProperties.getUsers();
		final PasswordConstraints usersPasswordContraints = PasswordConstraintsUtil.proxy(usersProperties);
		return usersPasswordContraints;
	}

	private PasswordConstraints clientsPasswordConstraints() {
		final Clients clientsProperties = this.springsUtilSecurityPasswordsProperties.getClients();
		final PasswordConstraints clientsPasswordContraints = PasswordConstraintsUtil.proxy(clientsProperties);
		return clientsPasswordContraints;
	}

	private PasswordConstraints serverPasswordContraints() {
		final Servers serversProperties = this.springsUtilSecurityPasswordsProperties.getServers();
		final PasswordConstraints serverPasswordContraints = PasswordConstraintsUtil.proxy(serversProperties);
		return serverPasswordContraints;
	}

	private PasswordConstraints defaultsPasswordContraints() {
		final Defaults defaultsProperties = this.springsUtilSecurityPasswordsProperties.getDefaults();
		final PasswordConstraints defaultsPasswordContraints = PasswordConstraintsUtil.proxy(defaultsProperties);
		return defaultsPasswordContraints;
	}
}
