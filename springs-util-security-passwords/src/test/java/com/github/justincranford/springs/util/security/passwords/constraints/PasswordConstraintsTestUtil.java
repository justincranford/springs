package com.github.justincranford.springs.util.security.passwords.constraints;

import static org.mockito.Mockito.when;

import org.mockito.Mockito;

import com.github.justincranford.springs.util.security.passwords.properties.SpringsUtilSecurityPasswordsProperties;

public class PasswordConstraintsTestUtil {
	public static PasswordConstraints passwordConstraints(final SpringsUtilSecurityPasswordsProperties.Properties properties) {
		final PasswordConstraints mockPasswordConstraints = Mockito.mock(PasswordConstraints.class);
        when(mockPasswordConstraints.minLength()).thenReturn(properties.getMinLength());
        when(mockPasswordConstraints.maxLength()).thenReturn(properties.getMaxLength());
        when(mockPasswordConstraints.minUppers()).thenReturn(properties.getMinUppers());
        when(mockPasswordConstraints.maxUppers()).thenReturn(properties.getMaxUppers());
        when(mockPasswordConstraints.minLowers()).thenReturn(properties.getMinLowers());
        when(mockPasswordConstraints.maxLowers()).thenReturn(properties.getMaxLowers());
        when(mockPasswordConstraints.minDigits()).thenReturn(properties.getMinDigits());
        when(mockPasswordConstraints.maxDigits()).thenReturn(properties.getMaxDigits());
        when(mockPasswordConstraints.minSpecials()).thenReturn(properties.getMinSpecials());
        when(mockPasswordConstraints.maxSpecials()).thenReturn(properties.getMaxSpecials());
        when(mockPasswordConstraints.minWhitespace()).thenReturn(properties.getMinWhitespace());
        when(mockPasswordConstraints.maxWhitespace()).thenReturn(properties.getMaxWhitespace());
        when(mockPasswordConstraints.maxAnywhereRepeats()).thenReturn(properties.getMaxAnywhereRepeats());
        when(mockPasswordConstraints.maxConsecutiveRepeats()).thenReturn(properties.getMaxConsecutiveRepeats());
        when(mockPasswordConstraints.specials()).thenReturn(properties.getSpecials());
		return mockPasswordConstraints;
	}
}
