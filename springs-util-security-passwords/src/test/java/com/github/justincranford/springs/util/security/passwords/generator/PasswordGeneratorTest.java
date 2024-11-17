package com.github.justincranford.springs.util.security.passwords.generator;

import com.github.justincranford.springs.util.security.passwords.constraints.PasswordConstraints;
import com.github.justincranford.springs.util.security.passwords.properties.SpringsUtilSecurityPasswordsProperties;
import com.github.justincranford.springs.util.security.passwords.validator.PasswordValidator;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static com.github.justincranford.springs.util.security.passwords.constraints.PasswordConstraintsUtil.proxy;

@ExtendWith(SpringExtension.class)
@SuppressWarnings({ "static-method" })
public class PasswordGeneratorTest {
    @RepeatedTest(PasswordGeneratorTestUtil.REPEATS)
    public void testGeneratePassword_defaults() {
        final PasswordConstraints passwordConstraints = proxy(new SpringsUtilSecurityPasswordsProperties.Properties());
        final PasswordGenerator passwordGenerator = PasswordGenerator.create(passwordConstraints);
        final PasswordValidator passwordValidator = PasswordValidator.create(passwordConstraints);
        PasswordGeneratorTestUtil.generateAndValidate(passwordGenerator, passwordValidator);
    }
}
