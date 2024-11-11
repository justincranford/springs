package com.github.justincranford.springs.util.security.passwords.generator;

import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.github.justincranford.springs.util.security.passwords.validator.PasswordConstraintsValidator;

import jakarta.validation.ConstraintValidatorContext;

@ExtendWith(SpringExtension.class)
public class PasswordGeneratorTestUtil {
	public static final int REPEATS = 10;
    private static final ConstraintValidatorContext CONSTRAINT_VALIDATOR_CONTEXT = Mockito.mock(ConstraintValidatorContext.class);

	public static void generateAndValidate(final PasswordGenerator passwordGenerator, final PasswordConstraintsValidator passwordConstraintsValidator) {
		final String password = passwordGenerator.generate();
        assertTrue(passwordConstraintsValidator.isValid(password, CONSTRAINT_VALIDATOR_CONTEXT));
	}
}
