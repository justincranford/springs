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
import com.github.justincranford.springs.util.security.passwords.validator.PasswordConstraintsValidator;
import com.github.justincranford.springs.util.security.passwords.validator.PasswordConstraintsValidatorUtil;

import lombok.RequiredArgsConstructor;

@Configuration
@RequiredArgsConstructor
public class PasswordGeneratorConfiguration {
	@Autowired
	private final SpringsUtilSecurityPasswordsProperties springsUtilSecurityPasswordsProperties;

	@Bean
	public PasswordGenerator usersPasswordGenerator() {
		final Users usersProperties = this.springsUtilSecurityPasswordsProperties.getUsers();
		final PasswordConstraints usersPasswordContraints = PasswordConstraintsUtil.proxy(usersProperties);
		return new PasswordGenerator(usersPasswordContraints);
	}

	@Bean
	public PasswordGenerator clientsPasswordGenerator() {
		final Clients clientsProperties = this.springsUtilSecurityPasswordsProperties.getClients();
		final PasswordConstraints clientsPasswordContraints = PasswordConstraintsUtil.proxy(clientsProperties);
		return new PasswordGenerator(clientsPasswordContraints);
	}

	@Bean
	public PasswordGenerator serversPasswordGenerator() {
		final Servers serversProperties = this.springsUtilSecurityPasswordsProperties.getServers();
		final PasswordConstraints serverPasswordContraints = PasswordConstraintsUtil.proxy(serversProperties);
		return new PasswordGenerator(serverPasswordContraints);
	}

	@Bean
	public PasswordGenerator defaultsPasswordGenerator() {
		final Defaults defaultsProperties = this.springsUtilSecurityPasswordsProperties.getDefaults();
		final PasswordConstraints defaultsPasswordContraints = PasswordConstraintsUtil.proxy(defaultsProperties);
		return new PasswordGenerator(defaultsPasswordContraints);
	}

	@Bean
	public PasswordConstraintsValidator usersPasswordConstraintsValidator() {
		final Users usersProperties = this.springsUtilSecurityPasswordsProperties.getUsers();
		final PasswordConstraints usersPasswordContraints = PasswordConstraintsUtil.proxy(usersProperties);
		return PasswordConstraintsValidatorUtil.validator(usersPasswordContraints);
	}

	@Bean
	public PasswordConstraintsValidator clientsPasswordConstraintsValidator() {
		final Clients clientsProperties = this.springsUtilSecurityPasswordsProperties.getClients();
		final PasswordConstraints clientsPasswordContraints = PasswordConstraintsUtil.proxy(clientsProperties);
		return PasswordConstraintsValidatorUtil.validator(clientsPasswordContraints);
	}

	@Bean
	public PasswordConstraintsValidator serversPasswordConstraintsValidator() {
		final Servers serversProperties = this.springsUtilSecurityPasswordsProperties.getServers();
		final PasswordConstraints serverPasswordContraints = PasswordConstraintsUtil.proxy(serversProperties);
		return PasswordConstraintsValidatorUtil.validator(serverPasswordContraints);
	}

	@Bean
	public PasswordConstraintsValidator defaultsPasswordConstraintsValidator() {
		final Defaults defaultsProperties = this.springsUtilSecurityPasswordsProperties.getDefaults();
		final PasswordConstraints defaultsPasswordContraints = PasswordConstraintsUtil.proxy(defaultsProperties);
		return PasswordConstraintsValidatorUtil.validator(defaultsPasswordContraints);
	}
}
