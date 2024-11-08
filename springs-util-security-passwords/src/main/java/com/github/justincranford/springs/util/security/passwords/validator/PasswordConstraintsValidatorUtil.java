package com.github.justincranford.springs.util.security.passwords.validator;

import com.github.justincranford.springs.util.security.passwords.constraints.PasswordConstraints;

public class PasswordConstraintsValidatorUtil {
	public static PasswordConstraintsValidator validator(PasswordConstraints passwordConstraints) {
		final PasswordConstraintsValidator passwordConstraintsValidator = new PasswordConstraintsValidator();
		passwordConstraintsValidator.initialize(passwordConstraints);
		return passwordConstraintsValidator;
	}	
}
