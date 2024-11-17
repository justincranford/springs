package com.github.justincranford.springs.util.security.passwords.generator;

import com.github.justincranford.springs.util.security.passwords.validator.PasswordValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(SpringExtension.class)
public class PasswordGeneratorTestUtil {
    public static final int REPEATS = 10;
    private static final ConstraintValidatorContext CONSTRAINT_VALIDATOR_CONTEXT = Mockito.mock(ConstraintValidatorContext.class);

    public static void generateAndValidate(final PasswordGenerator passwordGenerator, final PasswordValidator passwordConstraintsValidator) {
        final String password = passwordGenerator.generate();
        assertTrue(passwordConstraintsValidator.isValid(password, CONSTRAINT_VALIDATOR_CONTEXT));
    }
}
