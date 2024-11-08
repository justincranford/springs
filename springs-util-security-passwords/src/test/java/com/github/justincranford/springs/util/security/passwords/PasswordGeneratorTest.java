package com.github.justincranford.springs.util.security.passwords;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.github.justincranford.springs.util.security.passwords.properties.SpringsUtilSecurityPasswordsProperties;

import jakarta.validation.ConstraintValidatorContext;

@ExtendWith(SpringExtension.class)
@SuppressWarnings({"nls", "unused", "boxing", "static-method"})
public class PasswordGeneratorTest {
    private static final ConstraintValidatorContext CONSTRAINT_VALIDATOR_CONTEXT = Mockito.mock(ConstraintValidatorContext.class);

    @RepeatedTest(100)
    public void testGeneratePassword_withMockedPasswordStrength() {
		final SpringsUtilSecurityPasswordsProperties.Properties springsUtilSecurityPasswordsProperties = new SpringsUtilSecurityPasswordsProperties.Properties();
        final PasswordStrength mockPasswordStrength = createPasswordStrengthProxy(springsUtilSecurityPasswordsProperties);
        String password = PasswordGenerator.generatePassword(mockPasswordStrength);
        final PasswordStrengthValidator passwordStrengthValidator = createPasswordStrengthValidator(mockPasswordStrength);
        passwordStrengthValidator.isValid(password, CONSTRAINT_VALIDATOR_CONTEXT);
        assertNotNull(password, "Password should not be null");
        assertTrue(password.length() >= mockPasswordStrength.minLength(), "Password should meet minLength");
        assertTrue(password.length() <= mockPasswordStrength.maxLength(), "Password should not exceed maxLength");
    }

	private static PasswordStrengthValidator createPasswordStrengthValidator(PasswordStrength passwordStrength) {
		final PasswordStrengthValidator passwordStrengthValidator = new PasswordStrengthValidator();
		passwordStrengthValidator.initialize(passwordStrength);
		return passwordStrengthValidator;
    }

	private static PasswordStrength mockPasswordStrength(final SpringsUtilSecurityPasswordsProperties.Properties properties) {
		final PasswordStrength mockPasswordStrength = Mockito.mock(PasswordStrength.class);
        when(mockPasswordStrength.minLength()).thenReturn(properties.getMinLength());
        when(mockPasswordStrength.maxLength()).thenReturn(properties.getMaxLength());
        when(mockPasswordStrength.minUppers()).thenReturn(properties.getMinUppers());
        when(mockPasswordStrength.maxUppers()).thenReturn(properties.getMaxUppers());
        when(mockPasswordStrength.minLowers()).thenReturn(properties.getMinLowers());
        when(mockPasswordStrength.maxLowers()).thenReturn(properties.getMaxLowers());
        when(mockPasswordStrength.minDigits()).thenReturn(properties.getMinDigits());
        when(mockPasswordStrength.maxDigits()).thenReturn(properties.getMaxDigits());
        when(mockPasswordStrength.minSpecials()).thenReturn(properties.getMinSpecials());
        when(mockPasswordStrength.maxSpecials()).thenReturn(properties.getMaxSpecials());
        when(mockPasswordStrength.minWhitespace()).thenReturn(properties.getMinWhitespace());
        when(mockPasswordStrength.maxWhitespace()).thenReturn(properties.getMaxWhitespace());
        when(mockPasswordStrength.maxAnywhereRepeats()).thenReturn(properties.getMaxAnywhereRepeats());
        when(mockPasswordStrength.maxConsecutiveRepeats()).thenReturn(properties.getMaxConsecutiveRepeats());
        when(mockPasswordStrength.specials()).thenReturn(properties.getSpecials());
		return mockPasswordStrength;
	}

	private static PasswordStrength createPasswordStrengthProxy(final SpringsUtilSecurityPasswordsProperties.Properties properties) {
	    return (PasswordStrength) Proxy.newProxyInstance(
	        PasswordStrength.class.getClassLoader(),
	        new Class[]{PasswordStrength.class},
	        new InvocationHandler() {
	            @Override
	            public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
	                switch (method.getName()) {
	                    case "minLength": return properties.getMinLength();
	                    case "maxLength": return properties.getMaxLength();
	                    case "minUppers": return properties.getMinUppers();
	                    case "maxUppers": return properties.getMaxUppers();
	                    case "minLowers": return properties.getMinLowers();
	                    case "maxLowers": return properties.getMaxLowers();
	                    case "minDigits": return properties.getMinDigits();
	                    case "maxDigits": return properties.getMaxDigits();
	                    case "minSpecials": return properties.getMinSpecials();
	                    case "maxSpecials": return properties.getMaxSpecials();
	                    case "minWhitespace": return properties.getMinWhitespace();
	                    case "maxWhitespace": return properties.getMaxWhitespace();
	                    case "maxAnywhereRepeats": return properties.getMaxAnywhereRepeats();
	                    case "maxConsecutiveRepeats": return properties.getMaxConsecutiveRepeats();
	                    case "specials": return properties.getSpecials();
	                    default: return method.getDefaultValue();
	                }
	            }
	        }
	    );
	}
}
