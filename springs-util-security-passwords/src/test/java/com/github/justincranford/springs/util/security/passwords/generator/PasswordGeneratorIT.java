package com.github.justincranford.springs.util.security.passwords.generator;

import org.junit.jupiter.api.RepeatedTest;

import com.github.justincranford.springs.util.security.passwords.AbstractIT;

public class PasswordGeneratorIT extends AbstractIT {
	@RepeatedTest(PasswordGeneratorTestUtil.REPEATS)
    public void testGeneratePassword_usersProperties() {
		PasswordGeneratorTestUtil.generateAndValidate(super.usersPasswordGenerator(), super.usersPasswordValidator());
    }

	@RepeatedTest(PasswordGeneratorTestUtil.REPEATS)
    public void testGeneratePassword_clientsProperties() {
		PasswordGeneratorTestUtil.generateAndValidate(super.clientsPasswordGenerator(), super.clientsPasswordValidator());
    }

	@RepeatedTest(PasswordGeneratorTestUtil.REPEATS)
    public void testGeneratePassword_serversProperties() {
		PasswordGeneratorTestUtil.generateAndValidate(super.serversPasswordGenerator(), super.serversPasswordValidator());
    }

	@RepeatedTest(PasswordGeneratorTestUtil.REPEATS)
    public void testGeneratePassword_defaultsProperties() {
		PasswordGeneratorTestUtil.generateAndValidate(super.defaultsPasswordGenerator(), super.defaultsPasswordValidator());
    }
}
