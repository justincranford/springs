package com.github.justincranford.springs.util.security.passwords;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import jakarta.validation.ConstraintValidatorContext;

@ExtendWith(SpringExtension.class)
@SuppressWarnings({"nls", "boxing", "static-method"})
public class PasswordGeneratorTest {
	@RepeatedTest(10)
    public void testGeneratePassword_withMockedPasswordStrength() {
        final PasswordStrength mockPasswordStrength = mockPasswordStrength();
        String password = PasswordGenerator.generatePassword(mockPasswordStrength);
        final PasswordStrengthValidator passwordStrengthValidator = createPasswordStrengthValidator(mockPasswordStrength);
        final ConstraintValidatorContext constraintValidatorContext = Mockito.mock(ConstraintValidatorContext.class);
        passwordStrengthValidator.isValid(password, constraintValidatorContext);
        assertNotNull(password, "Password should not be null");
        assertTrue(password.length() >= mockPasswordStrength.minLength(), "Password should meet minLength");
        assertTrue(password.length() <= mockPasswordStrength.maxLength(), "Password should not exceed maxLength");
    }

	private static PasswordStrengthValidator createPasswordStrengthValidator(PasswordStrength passwordStrength) {
		final PasswordStrengthValidator passwordStrengthValidator = new PasswordStrengthValidator();
		passwordStrengthValidator.initialize(passwordStrength);
		return passwordStrengthValidator;
    }

	private static PasswordStrength mockPasswordStrength() {
		final PasswordStrength mockPasswordStrength = Mockito.mock(PasswordStrength.class);
        Mockito.when(mockPasswordStrength.minLength()).thenReturn(12);
        Mockito.when(mockPasswordStrength.maxLength()).thenReturn(64);
        Mockito.when(mockPasswordStrength.minUppers()).thenReturn(2);
        Mockito.when(mockPasswordStrength.maxUppers()).thenReturn(5);
        Mockito.when(mockPasswordStrength.minLowers()).thenReturn(2);
        Mockito.when(mockPasswordStrength.maxLowers()).thenReturn(5);
        Mockito.when(mockPasswordStrength.minDigits()).thenReturn(2);
        Mockito.when(mockPasswordStrength.maxDigits()).thenReturn(5);
        Mockito.when(mockPasswordStrength.minSpecials()).thenReturn(1);
        Mockito.when(mockPasswordStrength.maxSpecials()).thenReturn(3);
        Mockito.when(mockPasswordStrength.minWhitespace()).thenReturn(0);
        Mockito.when(mockPasswordStrength.maxWhitespace()).thenReturn(1);
        Mockito.when(mockPasswordStrength.maxAnywhereRepeats()).thenReturn(3);
        Mockito.when(mockPasswordStrength.maxConsecutiveRepeats()).thenReturn(2);
        Mockito.when(mockPasswordStrength.specials()).thenReturn("!@#");
		return mockPasswordStrength;
	}
}
