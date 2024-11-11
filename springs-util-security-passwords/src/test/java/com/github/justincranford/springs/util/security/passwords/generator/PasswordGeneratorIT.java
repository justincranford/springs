package com.github.justincranford.springs.util.security.passwords.generator;

import org.junit.jupiter.api.RepeatedTest;

import com.github.justincranford.springs.util.security.passwords.AbstractIT;

public class PasswordGeneratorIT extends AbstractIT {
	@RepeatedTest(PasswordGeneratorTestUtil.REPEATS)
    public void testGeneratePassword_usersProperties() {
		PasswordGeneratorTestUtil.commonTest(springsUtilSecurityHashesProperties().getUsers());
    }

	@RepeatedTest(PasswordGeneratorTestUtil.REPEATS)
    public void testGeneratePassword_clientsProperties() {
		PasswordGeneratorTestUtil.commonTest(springsUtilSecurityHashesProperties().getClients());
    }

	@RepeatedTest(PasswordGeneratorTestUtil.REPEATS)
    public void testGeneratePassword_serversProperties() {
		PasswordGeneratorTestUtil.commonTest(springsUtilSecurityHashesProperties().getServers());
    }

	@RepeatedTest(PasswordGeneratorTestUtil.REPEATS)
    public void testGeneratePassword_defaultsProperties() {
		PasswordGeneratorTestUtil.commonTest(springsUtilSecurityHashesProperties().getDefaults());
    }
}
