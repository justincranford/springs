package com.github.justincranford.springs.util.security.passwords;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.github.justincranford.springs.util.security.passwords.properties.SpringsUtilSecurityPasswordsProperties;

import jakarta.validation.ConstraintValidatorContext;

@ExtendWith(SpringExtension.class)
@SuppressWarnings({"nls", "boxing", "static-method"})
public class PasswordGeneratorTest {
	@RepeatedTest(100)
    public void testGeneratePassword_withMockedPasswordStrength() {
		final SpringsUtilSecurityPasswordsProperties.Properties springsUtilSecurityPasswordsProperties = new SpringsUtilSecurityPasswordsProperties.Properties();
        final PasswordStrength mockPasswordStrength = mockPasswordStrength(springsUtilSecurityPasswordsProperties);
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

	private static PasswordStrength mockPasswordStrength(final SpringsUtilSecurityPasswordsProperties.Properties springsUtilSecurityPasswordsProperties) {
		final PasswordStrength mockPasswordStrength = Mockito.mock(PasswordStrength.class);
        Mockito.when(mockPasswordStrength.minLength()).thenReturn(springsUtilSecurityPasswordsProperties.getMinLength());
        Mockito.when(mockPasswordStrength.maxLength()).thenReturn(springsUtilSecurityPasswordsProperties.getMaxLength());
        Mockito.when(mockPasswordStrength.minUppers()).thenReturn(springsUtilSecurityPasswordsProperties.getMinUppers());
        Mockito.when(mockPasswordStrength.maxUppers()).thenReturn(springsUtilSecurityPasswordsProperties.getMaxUppers());
        Mockito.when(mockPasswordStrength.minLowers()).thenReturn(springsUtilSecurityPasswordsProperties.getMinLowers());
        Mockito.when(mockPasswordStrength.maxLowers()).thenReturn(springsUtilSecurityPasswordsProperties.getMaxLowers());
        Mockito.when(mockPasswordStrength.minDigits()).thenReturn(springsUtilSecurityPasswordsProperties.getMinDigits());
        Mockito.when(mockPasswordStrength.maxDigits()).thenReturn(springsUtilSecurityPasswordsProperties.getMaxDigits());
        Mockito.when(mockPasswordStrength.minSpecials()).thenReturn(springsUtilSecurityPasswordsProperties.getMinSpecials());
        Mockito.when(mockPasswordStrength.maxSpecials()).thenReturn(springsUtilSecurityPasswordsProperties.getMaxSpecials());
        Mockito.when(mockPasswordStrength.minWhitespace()).thenReturn(springsUtilSecurityPasswordsProperties.getMinWhitespace());
        Mockito.when(mockPasswordStrength.maxWhitespace()).thenReturn(springsUtilSecurityPasswordsProperties.getMaxWhitespace());
        Mockito.when(mockPasswordStrength.maxAnywhereRepeats()).thenReturn(springsUtilSecurityPasswordsProperties.getMaxAnywhereRepeats());
        Mockito.when(mockPasswordStrength.maxConsecutiveRepeats()).thenReturn(springsUtilSecurityPasswordsProperties.getMaxConsecutiveRepeats());
        Mockito.when(mockPasswordStrength.specials()).thenReturn(springsUtilSecurityPasswordsProperties.getSpecials());
		return mockPasswordStrength;
	}
}
