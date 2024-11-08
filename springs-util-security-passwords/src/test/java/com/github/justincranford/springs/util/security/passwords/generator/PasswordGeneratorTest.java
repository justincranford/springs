package com.github.justincranford.springs.util.security.passwords.generator;

import static com.github.justincranford.springs.util.security.passwords.constraints.PasswordConstraintsUtil.constraints;
import static com.github.justincranford.springs.util.security.passwords.generator.PasswordGenerator.generate;
import static com.github.justincranford.springs.util.security.passwords.validator.PasswordConstraintsValidatorUtil.validator;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.github.justincranford.springs.util.security.passwords.constraints.PasswordConstraints;
import com.github.justincranford.springs.util.security.passwords.properties.SpringsUtilSecurityPasswordsProperties;
import com.github.justincranford.springs.util.security.passwords.validator.PasswordConstraintsValidator;

import jakarta.validation.ConstraintValidatorContext;

@ExtendWith(SpringExtension.class)
@SuppressWarnings({"nls", "static-method"})
public class PasswordGeneratorTest {
    private static final ConstraintValidatorContext CONSTRAINT_VALIDATOR_CONTEXT = Mockito.mock(ConstraintValidatorContext.class);

    @RepeatedTest(100)
    public void testGeneratePassword_withMockedPasswordConstraints() {
		final SpringsUtilSecurityPasswordsProperties.Properties properties = new SpringsUtilSecurityPasswordsProperties.Properties();
        final PasswordConstraints passwordConstraints = constraints(properties);
        final String password = generate(passwordConstraints);
        final PasswordConstraintsValidator passwordConstraintsValidator = validator(passwordConstraints);
        assertTrue(passwordConstraintsValidator.isValid(password, CONSTRAINT_VALIDATOR_CONTEXT));
        assertNotNull(password, "Password should not be null");
        assertTrue(password.length() >= passwordConstraints.minLength(), "Password should meet minLength");
        assertTrue(password.length() <= passwordConstraints.maxLength(), "Password should not exceed maxLength");
    }
}
