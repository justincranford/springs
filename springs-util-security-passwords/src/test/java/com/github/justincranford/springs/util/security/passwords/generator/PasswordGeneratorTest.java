package com.github.justincranford.springs.util.security.passwords.generator;

import static com.github.justincranford.springs.util.security.passwords.constraints.PasswordConstraintsUtil.proxy;
import static com.github.justincranford.springs.util.security.passwords.validator.PasswordConstraintsValidatorUtil.validator;

import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.github.justincranford.springs.util.security.passwords.constraints.PasswordConstraints;
import com.github.justincranford.springs.util.security.passwords.properties.SpringsUtilSecurityPasswordsProperties;
import com.github.justincranford.springs.util.security.passwords.validator.PasswordConstraintsValidator;

@ExtendWith(SpringExtension.class)
@SuppressWarnings({"static-method"})
public class PasswordGeneratorTest {
    @RepeatedTest(PasswordGeneratorTestUtil.REPEATS)
    public void testGeneratePassword_defaults() {
		final PasswordConstraints          passwordConstraints          = proxy(new SpringsUtilSecurityPasswordsProperties.Properties());
		final PasswordGenerator            passwordGenerator            = new PasswordGenerator(passwordConstraints);
        final PasswordConstraintsValidator passwordConstraintsValidator = validator(passwordConstraints);
		PasswordGeneratorTestUtil.generateAndValidate(passwordGenerator, passwordConstraintsValidator);
    }
}
