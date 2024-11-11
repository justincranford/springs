package com.github.justincranford.springs.util.security.passwords.generator;

import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.github.justincranford.springs.util.security.passwords.properties.SpringsUtilSecurityPasswordsProperties;

@ExtendWith(SpringExtension.class)
@SuppressWarnings({"static-method"})
public class PasswordGeneratorTest {
    @RepeatedTest(PasswordGeneratorTestUtil.REPEATS)
    public void testGeneratePassword_defaults() {
		PasswordGeneratorTestUtil.commonTest(new SpringsUtilSecurityPasswordsProperties.Properties());
    }
}
